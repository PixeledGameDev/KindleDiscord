const express = require('express');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const path = require('path');
const { Client, GatewayIntentBits, PermissionsBitField, ChannelType } = require('discord.js');

const app = express();
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// ---- Config (set these in Render's Environment tab, never in code) ----
const SITE_PASSWORD = process.env.SITE_PASSWORD;
const BOT_TOKEN = process.env.DISCORD_BOT_TOKEN;
const GUILD_ID = process.env.DISCORD_GUILD_ID;

if (!SITE_PASSWORD) {
  console.warn('WARNING: SITE_PASSWORD env var is not set.');
}
if (!BOT_TOKEN || !GUILD_ID) {
  console.warn('WARNING: DISCORD_BOT_TOKEN and/or DISCORD_GUILD_ID env vars are not set — chat features will not work.');
}

// ---- Bot setup ----
const MAX_CACHED_MESSAGES = 30;
const messageCaches = new Map(); // channelId -> [{ id, author, content, timestamp }]
let availableChannels = []; // [{ id, name }]
let bot = null;
let botReady = false;

function toMsg(m) {
  return {
    id: m.id,
    author: m.author.username,
    content: m.content,
    timestamp: m.createdTimestamp
  };
}

async function primeChannelCache(channelId) {
  if (messageCaches.has(channelId)) return;
  try {
    const channel = await bot.channels.fetch(channelId);
    const history = await channel.messages.fetch({ limit: MAX_CACHED_MESSAGES });
    messageCaches.set(channelId, Array.from(history.values()).reverse().map(toMsg));
  } catch (err) {
    console.error(`Failed to prime cache for channel ${channelId}:`, err.message);
    messageCaches.set(channelId, []);
  }
}

if (BOT_TOKEN && GUILD_ID) {
  bot = new Client({
    intents: [
      GatewayIntentBits.Guilds,
      GatewayIntentBits.GuildMessages,
      GatewayIntentBits.MessageContent
    ]
  });

  bot.once('ready', async () => {
    console.log(`Bot logged in as ${bot.user.tag}`);
    try {
      const guild = await bot.guilds.fetch(GUILD_ID);
      const channels = await guild.channels.fetch();
      availableChannels = channels
        .filter(c => c && c.type === ChannelType.GuildText)
        .filter(c => {
          const perms = c.permissionsFor(bot.user);
          return perms && perms.has(PermissionsBitField.Flags.ViewChannel) && perms.has(PermissionsBitField.Flags.SendMessages);
        })
        .map(c => ({ id: c.id, name: c.name }))
        .sort((a, b) => a.name.localeCompare(b.name));
      console.log(`Found ${availableChannels.length} usable channels.`);
      botReady = true;
    } catch (err) {
      console.error('Failed to load channel list:', err.message);
    }
  });

  bot.on('messageCreate', (msg) => {
    if (!availableChannels.some(c => c.id === msg.channelId)) return;
    const cache = messageCaches.get(msg.channelId) || [];
    cache.push(toMsg(msg));
    messageCaches.set(msg.channelId, cache.length > MAX_CACHED_MESSAGES ? cache.slice(-MAX_CACHED_MESSAGES) : cache);
  });

  bot.login(BOT_TOKEN).catch(err => console.error('Bot login failed:', err.message));
}

// ---- In-memory session store (fine for a single small Render instance) ----
const sessions = new Map(); // token -> expiry timestamp
const SESSION_TTL_MS = 1000 * 60 * 60 * 4; // 4 hours

function makeSession() {
  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, Date.now() + SESSION_TTL_MS);
  return token;
}

function isValidSession(token) {
  if (!token || !sessions.has(token)) return false;
  const expiry = sessions.get(token);
  if (Date.now() > expiry) {
    sessions.delete(token);
    return false;
  }
  return true;
}

setInterval(() => {
  const now = Date.now();
  for (const [token, expiry] of sessions.entries()) {
    if (now > expiry) sessions.delete(token);
  }
}, 1000 * 60 * 10);

// ---- Basic rate limiting on login attempts, per IP ----
const loginAttempts = new Map(); // ip -> { count, resetAt }
const MAX_ATTEMPTS = 8;
const WINDOW_MS = 1000 * 60 * 10; // 10 minutes

function isRateLimited(ip) {
  const now = Date.now();
  const entry = loginAttempts.get(ip);
  if (!entry || now > entry.resetAt) {
    loginAttempts.set(ip, { count: 1, resetAt: now + WINDOW_MS });
    return false;
  }
  entry.count += 1;
  return entry.count > MAX_ATTEMPTS;
}

// ---- Auth routes ----

app.post('/api/login', (req, res) => {
  const ip = req.ip;
  if (isRateLimited(ip)) {
    return res.status(429).json({ error: 'Too many attempts. Try again later.' });
  }

  const { password } = req.body || {};
  if (typeof password !== 'string' || !SITE_PASSWORD) {
    return res.status(400).json({ error: 'Bad request.' });
  }

  const a = Buffer.from(password);
  const b = Buffer.from(SITE_PASSWORD);
  const match = a.length === b.length && crypto.timingSafeEqual(a, b);

  if (!match) {
    return res.status(401).json({ error: 'Incorrect password.' });
  }

  const token = makeSession();
  res.cookie('session', token, {
    httpOnly: true,
    secure: true,
    sameSite: 'strict',
    maxAge: SESSION_TTL_MS
  });
  res.json({ ok: true });
});

app.post('/api/logout', (req, res) => {
  const token = req.cookies.session;
  if (token) sessions.delete(token);
  res.clearCookie('session');
  res.json({ ok: true });
});

app.get('/api/check', (req, res) => {
  res.json({ authenticated: isValidSession(req.cookies.session) });
});

// ---- Chat routes ----

app.get('/api/channels', (req, res) => {
  if (!isValidSession(req.cookies.session)) {
    return res.status(401).json({ error: 'Not authenticated.' });
  }
  if (!botReady) {
    return res.status(503).json({ error: 'Bot is still starting up, try again shortly.' });
  }
  res.json({ channels: availableChannels });
});

app.get('/api/messages', async (req, res) => {
  if (!isValidSession(req.cookies.session)) {
    return res.status(401).json({ error: 'Not authenticated.' });
  }
  const channelId = req.query.channelId;
  if (!channelId || !availableChannels.some(c => c.id === channelId)) {
    return res.status(400).json({ error: 'Unknown or missing channelId.' });
  }

  await primeChannelCache(channelId);
  const cache = messageCaches.get(channelId) || [];

  const since = parseInt(req.query.since, 10);
  const messages = Number.isFinite(since) ? cache.filter(m => m.timestamp > since) : cache;
  res.json({ messages });
});

app.post('/api/send', async (req, res) => {
  if (!isValidSession(req.cookies.session)) {
    return res.status(401).json({ error: 'Not authenticated.' });
  }
  if (!botReady) {
    return res.status(503).json({ error: 'Bot is not ready yet.' });
  }

  const { channelId, content } = req.body || {};
  if (!channelId || !availableChannels.some(c => c.id === channelId)) {
    return res.status(400).json({ error: 'Unknown or missing channelId.' });
  }
  if (typeof content !== 'string' || !content.trim()) {
    return res.status(400).json({ error: 'Message content is required.' });
  }

  try {
    const channel = await bot.channels.fetch(channelId);
    await channel.send(content.trim().slice(0, 2000));
    return res.json({ ok: true });
  } catch (err) {
    console.error(err);
    return res.status(502).json({ error: `Failed to send: ${err.message}` });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
