import express from 'express';
import { createServer } from 'node:http';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { Server } from 'socket.io';
import pg from 'pg';
import crypto from 'crypto';
import multer from 'multer';
import { v2 as cloudinary } from 'cloudinary';
import { Readable } from 'stream';
import bcrypt from 'bcrypt';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';

const { Pool } = pg;

// ========== СПИСОК АДМИНИСТРАТОРОВ ==========
const ADMINS = new Set(['JohnyDuck', 'JohnyDuck_v2']);

function isAdmin(username) {
  return ADMINS.has(username);
}

// ========== ПОДКЛЮЧЕНИЕ К POSTGRESQL ==========
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL
    ? { rejectUnauthorized: false }
    : false,
});

// Вспомогательная обёртка для удобства
const db = {
  run: (text, params = []) => pool.query(text, params),
  get: async (text, params = []) => {
    const res = await pool.query(text, params);
    return res.rows[0] || null;
  },
  all: async (text, params = []) => {
    const res = await pool.query(text, params);
    return res.rows;
  },
};

// ========== ИНИЦИАЛИЗАЦИЯ ТАБЛИЦ ==========
await db.run(`
  CREATE TABLE IF NOT EXISTS messages (
    id SERIAL PRIMARY KEY,
    client_offset TEXT UNIQUE,
    content TEXT,
    username TEXT,
    msg_type TEXT DEFAULT 'text',
    file_type TEXT,
    profile_data TEXT
  )
`);

await db.run(`
  CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    token TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    last_login TIMESTAMPTZ
  )
`);

await db.run(`
  CREATE TABLE IF NOT EXISTS bans (
    id SERIAL PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    reason TEXT,
    banned_by TEXT,
    banned_at TIMESTAMPTZ DEFAULT NOW()
  )
`);

await db.run(`
  CREATE TABLE IF NOT EXISTS reactions (
    id SERIAL PRIMARY KEY,
    message_id INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    username TEXT NOT NULL,
    emoji TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(message_id, username)
  )
`);

// Индексы для ускорения запросов
await db.run(`CREATE INDEX IF NOT EXISTS idx_reactions_message ON reactions(message_id)`);
// Добавляем created_at если таблица была создана без неё (миграция)
await db.run(`ALTER TABLE reactions ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT NOW()`);
await db.run(`CREATE INDEX IF NOT EXISTS idx_users_token ON users(token)`);
await db.run(`CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)`);
await db.run(`CREATE INDEX IF NOT EXISTS idx_bans_username ON bans(username)`);

// ========== НАСТРОЙКА CLOUDINARY ==========
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key:    process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

const app = express();
const server = createServer(app);

// ========== SECURITY HEADERS (Helmet) ==========
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc:  ["'self'", "'unsafe-inline'", "https://cdn.socket.io", "https://cdn.jsdelivr.net"],
      styleSrc:   ["'self'", "'unsafe-inline'"],
      imgSrc:     ["'self'", "data:", "https://res.cloudinary.com", "https://cdn.jsdelivr.net", "https://media.giphy.com", "https://media0.giphy.com", "https://media1.giphy.com", "https://media2.giphy.com", "https://media3.giphy.com", "https://media4.giphy.com", "https://i.giphy.com", "https://media.tenor.com", "blob:"],
      mediaSrc:   ["'self'", "https://res.cloudinary.com", "blob:"],
      connectSrc: ["'self'", "wss:", "ws:", "https://api.giphy.com", "https://tenor.googleapis.com", "https://cdn.jsdelivr.net"],
    },
  },
  crossOriginEmbedderPolicy: false, // нужно для socket.io
}));

// ========== RATE LIMITING ==========
// Защита от брутфорса на логин/регистрацию
const authLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 минут
  max: 5,                   // не более 5 попыток на IP
  message: { error: 'Слишком много попыток. Подождите 1 минуту.' },
  standardHeaders: true,
  legacyHeaders: false,
});

// Общий лимит для API
const apiLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 минута
  max: 100,
  message: { error: 'Слишком много запросов.' },
  standardHeaders: true,
  legacyHeaders: false,
});

app.use('/api/', apiLimiter);
app.use('/api/login', authLimiter);
app.use('/api/register', authLimiter);

// ========== GIF (Giphy / Tenor API + локальный каталог, прокси только для скачивания) ==========
const GIPHY_API_KEY = process.env.GIPHY_API_KEY || '';
const TENOR_API_KEY = process.env.TENOR_API_KEY || '';
const TENOR_CLIENT_KEY = process.env.TENOR_CLIENT_KEY || 'mallard_chat';

const GIF_ALLOWED_HOSTS = new Set([
  'media.giphy.com', 'i.giphy.com',
  'media0.giphy.com', 'media1.giphy.com', 'media2.giphy.com', 'media3.giphy.com', 'media4.giphy.com',
  'media.tenor.com', 'c.tenor.com', 'media1.tenor.com',
]);

const GIF_CAT_QUERIES = {
  top: 'reaction wow excited',
  laugh: 'funny laugh lol meme',
  love: 'love heart cute kiss',
  react: 'thumbs up yes ok agree',
};

/** Рабочий URL: только /giphy.gif (превью 200.gif у Giphy часто 404) */
function giphyGif(id, tags) {
  const url = `https://media2.giphy.com/media/${id}/giphy.gif`;
  return { id, url, preview: url, tags: tags || '' };
}

const GIPHY_LIBRARY = [
  giphyGif('3o7abKhOud0GFozhvy', 'огонь топ круто reaction'),
  giphyGif('l3q2K5jinAlChoCLS', 'смех лол офис funny laugh'),
  giphyGif('26BRvHaY6Lo44TSJW', 'любовь сердце love heart'),
  giphyGif('13CoXDiaCcGyw', 'ржака смех laugh funny'),
  giphyGif('3o7btMw9k9wTuOCCeE', 'кот клавиатура cat typing'),
  giphyGif('npUElWVyhnv2U', 'класс палец вверх thumbs up'),
  giphyGif('gJWHjSuNG6PC', 'лол смешно funny'),
  giphyGif('FEib0sOPT3q00', 'милота cute'),
  giphyGif('3o6fJ1BM7R2EBRDnVS', 'прикол мем meme'),
  giphyGif('111ebjEgQAvzFu', 'ржу угар laugh'),
  giphyGif('l0MYGbRlnMizJDlz2', 'смеюсь funny'),
  giphyGif('26uLn0F94x9KDnsZq', 'хохот laugh'),
  giphyGif('l0HlHFRbwmfcEDITe', 'весело happy'),
  giphyGif('l2QDM9JhzFsFybVR2', 'мило cute love'),
  giphyGif('3o7abLDyz9DHRYez7e', 'поцелуй love kiss'),
  giphyGif('l46CyJri7tuZmKz5K', 'обнимашки hug love'),
  giphyGif('3o7abKGyGoJXTSjFi', 'романтика love'),
  giphyGif('MAj0BXKtOZDQ4', 'аплодисменты clap yes'),
  giphyGif('3o7TKSj8rEqb1jJQU0', 'ок согласен yes ok'),
  giphyGif('M9pdNW858ryFw', 'реакция reaction wow'),
  giphyGif('Is1O1EIcRhaEI', 'вау шок wow'),
  giphyGif('xTiTnq8xyWzoakejBu', 'танец круто dance'),
  giphyGif('26BRuo6sGiloprRw6', 'люблю love'),
  giphyGif('l3V0wHY8joaFRPzW0', 'лайк thumbs'),
  giphyGif('ICOgUNjpvO0WI', 'супер yes'),
  giphyGif('5GoVLqeAIo5Pu', 'да ok agree'),
  giphyGif('3o6Zt4HU9HIwZuY3gk', 'привет wave hi'),
  giphyGif('11sBLlzs7QvIM', 'удивление wow'),
  giphyGif('3o6Zt8MgUuvS51ZV6E', 'понял ok'),
  giphyGif('l0HlNQ03J5JxX6lva', 'нежность love'),
  giphyGif('3o7abldb0gie3z1dry', 'сердце heart'),
  giphyGif('l0MYt5jPR6QX5pnqM', 'смешно laugh'),
  giphyGif('26ufdipQqU2lhNA4g', 'ржака lol'),
  giphyGif('xUPGcuomu1ciyTxztV', 'реакция reaction'),
  giphyGif('JIX9uzl2aj4M', 'мем meme'),
  giphyGif('3o7WTJ7R8uMw504ek', 'круто cool'),
  giphyGif('1n4FTlB9vZw46RoPxg', 'огонь fire'),
  giphyGif('8YnqKeAFRKvk', 'класс top'),
  giphyGif('HZl1aNHJ4kMFK', 'вау excited'),
  giphyGif('3o7abBcwscG9UVrKQ', 'да yes'),
  giphyGif('dXJtAKm9b0t3G', 'ок thumbs'),
  giphyGif('l0MHeRginNtxlX9Lq', 'happy радость'),
  giphyGif('CmN4sZcu0VKmO', 'reaction топ'),
  giphyGif('3oz8xDrz6sXwK8', 'funny лол'),
  giphyGif('3o7abGiZkpW3VayzGs', 'excited вау'),
  giphyGif('l0ErKAbJvo7N4p5q4', 'dance танец'),
  giphyGif('3o6Z1UG8a3ZXzi7Ha', 'love heart'),
  giphyGif('3o7TKUAlNH7yAYesu', 'yes да'),
  giphyGif('l0HlP5EY1jnrVz4iE', 'cute мило'),
  giphyGif('26n7rZPt44KWi0L4O', 'laugh смех'),
  giphyGif('3o7abltb3a3pPqWdyE', 'wow реакция'),
  giphyGif('l0MYt4McWMXQtDeuu', 'funny прикол'),
  giphyGif('8uvBXCYfOXNl', 'meme мем'),
  giphyGif('l0HlXyl5zm0fJ8p7q', 'love любовь'),
  giphyGif('lMvQ4uYXF1e6fNWrW', 'heart сердце'),
  giphyGif('xT5LMHxhC9lSzeczq', 'reaction ok'),
];

function pickStaticGifs(cat, q, limit = 28) {
  const words = (q || GIF_CAT_QUERIES[cat] || '').toLowerCase().split(/\s+/).filter(Boolean);
  let pool = GIPHY_LIBRARY;
  if (q) {
    pool = GIPHY_LIBRARY.filter(g => {
      const t = g.tags.toLowerCase();
      return words.some(w => t.includes(w));
    });
    if (pool.length < 8) pool = GIPHY_LIBRARY;
  } else if (cat && GIF_CAT_QUERIES[cat]) {
    const catWords = GIF_CAT_QUERIES[cat].split(/\s+/);
    const scored = GIPHY_LIBRARY.map(g => {
      const t = g.tags.toLowerCase();
      const score = catWords.filter(w => t.includes(w)).length;
      return { g, score };
    });
    scored.sort((a, b) => b.score - a.score);
    pool = scored.filter(x => x.score > 0).map(x => x.g);
    if (pool.length < 12) pool = GIPHY_LIBRARY;
  }
  const out = [];
  const seen = new Set();
  for (let i = 0; i < pool.length && out.length < limit; i++) {
    const g = pool[i];
    if (seen.has(g.id)) continue;
    seen.add(g.id);
    out.push(g);
  }
  for (let i = 0; out.length < limit && i < GIPHY_LIBRARY.length; i++) {
    const g = GIPHY_LIBRARY[i];
    if (!seen.has(g.id)) { seen.add(g.id); out.push(g); }
  }
  return out;
}

function mapGiphyApiItem(g) {
  const id = g.id;
  if (!id) return null;
  const url = g.images?.original?.url || `https://media2.giphy.com/media/${id}/giphy.gif`;
  const preview = `https://media2.giphy.com/media/${id}/giphy.gif`;
  const tags = `${(g.title || '').toLowerCase()} ${(g.tags || []).join(' ').toLowerCase()}`.trim();
  return { id, url, preview, tags };
}

function mapTenorItem(r) {
  const mf = r.media_formats || {};
  const url = mf.gif?.url || mf.mediumgif?.url;
  const preview = mf.tinygif?.url || mf.nanogif?.url || mf.gif?.url;
  if (!url) return null;
  const tags = `${(r.content_description || '').toLowerCase()} ${(r.tags || []).join(' ').toLowerCase()}`.trim();
  return { id: r.id, url, preview, tags };
}

async function fetchTenorGifs(query, limit = 28) {
  if (!TENOR_API_KEY) return [];
  const apiUrl = new URL('https://tenor.googleapis.com/v2/search');
  apiUrl.searchParams.set('q', query);
  apiUrl.searchParams.set('key', TENOR_API_KEY);
  apiUrl.searchParams.set('client_key', TENOR_CLIENT_KEY);
  apiUrl.searchParams.set('limit', String(Math.min(limit, 30)));
  apiUrl.searchParams.set('media_filter', 'gif,tinygif');
  const r = await fetch(apiUrl);
  const data = await r.json();
  return (data.results || []).map(mapTenorItem).filter(Boolean);
}

async function fetchGiphyApiGifs(query, limit = 28) {
  if (!GIPHY_API_KEY) return [];
  const apiUrl = new URL('https://api.giphy.com/v1/gifs/search');
  apiUrl.searchParams.set('api_key', GIPHY_API_KEY);
  apiUrl.searchParams.set('q', query);
  apiUrl.searchParams.set('limit', String(Math.min(limit, 30)));
  apiUrl.searchParams.set('rating', 'pg-13');
  apiUrl.searchParams.set('lang', 'ru');
  const r = await fetch(apiUrl);
  const data = await r.json();
  return (data.data || []).map(mapGiphyApiItem).filter(Boolean);
}

app.get('/api/gif-image', async (req, res) => {
  const raw = req.query.u;
  if (!raw || typeof raw !== 'string' || raw.length > 800) {
    return res.status(400).end();
  }
  let url;
  try {
    url = new URL(raw);
  } catch {
    return res.status(400).end();
  }
  if (url.protocol !== 'https:' || !GIF_ALLOWED_HOSTS.has(url.hostname)) {
    return res.status(403).end();
  }
  try {
    const upstream = await fetch(url.toString(), {
      headers: {
        Accept: 'image/*,*/*',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        Referer: url.hostname.includes('tenor') ? 'https://tenor.com/' : 'https://giphy.com/',
      },
      redirect: 'follow',
    });
    if (!upstream.ok) return res.status(upstream.status).end();
    const ct = upstream.headers.get('content-type') || 'image/gif';
    if (!ct.startsWith('image/') && !ct.includes('gif')) {
      return res.status(502).end();
    }
    const buf = Buffer.from(await upstream.arrayBuffer());
    if (buf.length < 200) return res.status(502).end();
    res.set('Content-Type', ct.split(';')[0] || 'image/gif');
    res.set('Cache-Control', 'public, max-age=604800');
    res.send(buf);
  } catch (err) {
    console.error('gif-image proxy:', err.message);
    res.status(502).end();
  }
});

app.get('/api/gifs', async (req, res) => {
  const cat = String(req.query.cat || 'top').slice(0, 16);
  const q = String(req.query.q || '').trim().slice(0, 48);
  const searchQ = q || GIF_CAT_QUERIES[cat] || GIF_CAT_QUERIES.top;

  if (TENOR_API_KEY) {
    try {
      const gifs = await fetchTenorGifs(searchQ, 28);
      if (gifs.length) return res.json({ ok: true, source: 'tenor', gifs });
    } catch (err) {
      console.error('Tenor API:', err.message);
    }
  }

  if (GIPHY_API_KEY) {
    try {
      const gifs = await fetchGiphyApiGifs(searchQ, 28);
      if (gifs.length) return res.json({ ok: true, source: 'giphy-api', gifs });
    } catch (err) {
      console.error('Giphy API:', err.message);
    }
  }

  const gifs = pickStaticGifs(cat, q, 28);
  res.json({ ok: true, source: 'giphy-static', gifs });
});

// ========== ЗАГРУЗКА ФАЙЛОВ ==========
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 50 * 1024 * 1024 }, // 50 MB
});

function uploadToCloudinary(buffer, mimetype, username) {
  return new Promise((resolve, reject) => {
    const resourceType = mimetype.startsWith('video/') ? 'video' : 'image';
    const folder = username ? `mallard_chat/${username}` : 'mallard_chat';
    const uploadStream = cloudinary.uploader.upload_stream(
      { resource_type: resourceType, folder },
      (error, result) => {
        if (error) reject(error);
        else resolve(result);
      }
    );
    Readable.from(buffer).pipe(uploadStream);
  });
}

app.post('/api/upload', upload.single('file'), async (req, res) => {
  const file = req.file;
  if (!file) return res.status(400).json({ error: 'Нет файла' });

  // Определяем юзернейм по токену из заголовка Authorization
  let uploaderUsername = null;
  const authHeader = req.headers['authorization'] || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  if (token) {
    try {
      const user = await db.get('SELECT username FROM users WHERE token = $1', [token]);
      if (user) uploaderUsername = user.username;
    } catch (_) {}
  }

  try {
    const result = await uploadToCloudinary(file.buffer, file.mimetype, uploaderUsername);
    const fileType = file.mimetype.startsWith('image/') ? 'image'
                   : file.mimetype.startsWith('video/') ? 'video'
                   : 'file';
    res.json({ url: result.secure_url, fileType });
  } catch (err) {
    console.error('Ошибка Cloudinary:', err);
    res.status(500).json({ error: 'Ошибка загрузки файла' });
  }
});

// ========== ХЕШИРОВАНИЕ ПАРОЛЕЙ (bcrypt) ==========
const BCRYPT_ROUNDS = 12; // высокая стоимость — защита от брутфорса

async function hashPassword(password) {
  return bcrypt.hash(password, BCRYPT_ROUNDS);
}

async function verifyPassword(password, hash) {
  return bcrypt.compare(password, hash);
}

// Безопасная генерация токена
function generateToken() {
  return crypto.randomBytes(48).toString('hex'); // 96 символов
}

// ========== ВАЛИДАЦИЯ ВХОДНЫХ ДАННЫХ ==========
function sanitizeUsername(username) {
  // Только буквы, цифры, _, - ; длина 3–32
  return /^[a-zA-Z0-9_\-а-яА-ЯёЁ]{3,32}$/.test(username);
}

// ========== API РЕГИСТРАЦИИ ==========
app.post('/api/register', express.json(), async (req, res) => {
  const { username, password } = req.body || {};

  if (!username || !password) {
    return res.status(400).json({ error: 'Логин и пароль обязательны' });
  }

  if (!sanitizeUsername(username)) {
    return res.status(400).json({ error: 'Логин: 3–32 символа, только буквы/цифры/_/-' });
  }

  if (password.length < 8) {
    return res.status(400).json({ error: 'Пароль — минимум 8 символов' });
  }

  if (password.length > 128) {
    return res.status(400).json({ error: 'Пароль слишком длинный' });
  }

  try {
    const existing = await db.get('SELECT id FROM users WHERE username = $1', [username]);
    if (existing) {
      return res.status(400).json({ error: 'Пользователь уже существует' });
    }

    const passwordHash = await hashPassword(password);
    const token = generateToken();

    await db.run(
      'INSERT INTO users (username, password_hash, token, last_login) VALUES ($1, $2, $3, NOW())',
      [username, passwordHash, token]
    );

    res.json({ token, username });
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// ========== API ЛОГИНА ==========
app.post('/api/login', express.json(), async (req, res) => {
  const { username, password } = req.body || {};

  if (!username || !password) {
    return res.status(400).json({ error: 'Неверный логин или пароль' });
  }

  try {
    const user = await db.get('SELECT * FROM users WHERE username = $1', [username]);

    // Единое сообщение — не раскрываем, есть ли такой логин
    if (!user) {
      // Всё равно выполняем сравнение, чтобы не допустить timing attack
      await bcrypt.compare(password, '$2b$12$invalidhashfortimingprotection000000000000000');
      return res.status(400).json({ error: 'Неверный логин или пароль' });
    }

    const valid = await verifyPassword(password, user.password_hash);
    if (!valid) {
      return res.status(400).json({ error: 'Неверный логин или пароль' });
    }

    const newToken = generateToken();
    await db.run(
      'UPDATE users SET token = $1, last_login = NOW() WHERE id = $2',
      [newToken, user.id]
    );

    res.json({ token: newToken, username: user.username });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// ========== ПРОВЕРКА ТОКЕНА ==========
app.post('/api/verify-token', express.json(), async (req, res) => {
  const { token } = req.body || {};
  if (!token || token.length > 200) return res.status(401).json({ valid: false });

  try {
    const user = await db.get('SELECT username FROM users WHERE token = $1', [token]);
    if (!user) return res.status(401).json({ valid: false });
    res.json({ valid: true, username: user.username });
  } catch (err) {
    res.status(500).json({ valid: false });
  }
});

// ========== SOCKET.IO ==========
const io = new Server(server, {
  connectionStateRecovery: {},
  // Защита от слишком больших сообщений
  maxHttpBufferSize: 1e6, // 1 MB
});

// Проверка токена при подключении
io.use(async (socket, next) => {
  const token = socket.handshake.auth.token;
  if (!token || typeof token !== 'string' || token.length > 200) {
    return next(new Error('Нет токена'));
  }

  try {
    const user = await db.get('SELECT username FROM users WHERE token = $1', [token]);
    if (!user) return next(new Error('Неверный токен'));

    socket.username = user.username;
    socket.isAdmin  = isAdmin(user.username);
    next();
  } catch (err) {
    next(new Error('Ошибка проверки токена'));
  }
});

const __dirname = dirname(fileURLToPath(import.meta.url));

app.use(express.static('public'));
app.use('/public', express.static('public'));

app.get('/', (req, res) => res.sendFile(join(__dirname, 'index.html')));
app.get('/login.html', (req, res) => res.sendFile(join(__dirname, 'login.html')));
app.get('/register.html', (req, res) => res.sendFile(join(__dirname, 'register.html')));

io.on('connection', async (socket) => {
  console.log(`Client connected: ${socket.username} (admin: ${socket.isAdmin})`);

  socket.emit('your role', { isAdmin: socket.isAdmin, username: socket.username });

  // ========== ОБРАБОТКА НОВОГО СООБЩЕНИЯ ==========
  socket.on('chat message', async (data, clientOffset, callback) => {
    try {
      const ban = await db.get('SELECT reason FROM bans WHERE username = $1', [socket.username]);
      if (ban) {
        socket.emit('banned', { reason: ban.reason });
        if (typeof callback === 'function') callback();
        return;
      }

      let msgText, msgUsername, msgType, fileType, profileData;

      if (data.type === 'file') {
        msgText     = data.url;
        msgUsername = socket.username; // берём из токена, а не от клиента!
        msgType     = 'file';
        fileType    = data.fileType;
      } else {
        if (typeof data.text !== 'string') {
          if (typeof callback === 'function') callback();
          return;
        }
        msgText     = data.text.substring(0, 4000); // ограничение длины
        msgUsername = socket.username; // только из токена
        msgType     = 'text';
        fileType    = null;
      }

      profileData = (data.profile && typeof data.profile === 'object')
        ? JSON.stringify(data.profile)
        : null;

      const safeOffset = (typeof clientOffset === 'string' && clientOffset.length < 200)
        ? clientOffset
        : null;

      let result;
      try {
        result = await db.run(
          'INSERT INTO messages (content, client_offset, username, msg_type, file_type, profile_data) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id',
          [msgText, safeOffset, msgUsername, msgType, fileType, profileData]
        );
      } catch (e) {
        if (typeof callback === 'function') callback();
        return;
      }

      const lastID = result.rows[0].id;

      const emitMsg = data.type === 'file'
        ? { type: 'file', fileType: data.fileType, url: data.url, username: msgUsername, profile: data.profile || {} }
        : { text: msgText, username: msgUsername, profile: data.profile || {} };

      io.emit('chat message', emitMsg, lastID);
      if (typeof callback === 'function') callback();
    } catch (err) {
      console.error('Message error:', err);
      if (typeof callback === 'function') callback();
    }
  });

  // ========== УДАЛЕНИЕ СООБЩЕНИЙ ==========
  socket.on('delete messages', async (ids, callback) => {
    if (!Array.isArray(ids) || ids.length === 0) return;

    // Ограничиваем количество за раз
    const safeIds = ids.slice(0, 100).map(Number).filter(n => Number.isInteger(n) && n > 0);
    if (safeIds.length === 0) return;

    try {
      const placeholders = safeIds.map((_, i) => `$${i + 1}`).join(',');
      let validIds;

      if (socket.isAdmin) {
        const rows = await db.all(
          `SELECT id FROM messages WHERE id IN (${placeholders})`,
          safeIds
        );
        validIds = rows.map(r => r.id);
      } else {
        const rows = await db.all(
          `SELECT id FROM messages WHERE id IN (${placeholders}) AND username = $${safeIds.length + 1}`,
          [...safeIds, socket.username]
        );
        validIds = rows.map(r => r.id);
      }

      if (validIds.length === 0) return;
      const ph2 = validIds.map((_, i) => `$${i + 1}`).join(',');
      await db.run(`DELETE FROM messages WHERE id IN (${ph2})`, validIds);
      io.emit('messages deleted', validIds);
      if (typeof callback === 'function') callback({ ok: true });
    } catch (e) {
      console.error('Delete error:', e);
      if (typeof callback === 'function') callback({ ok: false });
    }
  });

  // ========== БАН (только для админов) ==========
  socket.on('admin ban', async ({ targetUsername, reason }, callback) => {
    if (!socket.isAdmin) {
      if (typeof callback === 'function') callback({ ok: false, error: 'not admin' });
      return;
    }
    if (!targetUsername || typeof targetUsername !== 'string') {
      if (typeof callback === 'function') callback({ ok: false, error: 'no target' });
      return;
    }

    try {
      await db.run(
        'INSERT INTO bans (username, reason, banned_by) VALUES ($1, $2, $3) ON CONFLICT (username) DO UPDATE SET reason = $2, banned_by = $3, banned_at = NOW()',
        [targetUsername, reason || 'Нарушение правил', socket.username]
      );

      for (const [, s] of io.sockets.sockets) {
        if (s.username === targetUsername) {
          s.emit('banned', { reason: reason || 'Нарушение правил' });
        }
      }

      io.emit('user banned', { username: targetUsername });
      console.log(`[ADMIN] ${socket.username} banned ${targetUsername}: ${reason}`);
      if (typeof callback === 'function') callback({ ok: true });
    } catch (e) {
      console.error('Ban error:', e);
      if (typeof callback === 'function') callback({ ok: false, error: e.message });
    }
  });

  // ========== РАЗБАН ==========
  socket.on('admin unban', async ({ targetUsername }, callback) => {
    if (!socket.isAdmin) {
      if (typeof callback === 'function') callback({ ok: false, error: 'not admin' });
      return;
    }
    try {
      await db.run('DELETE FROM bans WHERE username = $1', [targetUsername]);
      io.emit('user unbanned', { username: targetUsername });
      console.log(`[ADMIN] ${socket.username} unbanned ${targetUsername}`);
      if (typeof callback === 'function') callback({ ok: true });
    } catch (e) {
      if (typeof callback === 'function') callback({ ok: false, error: e.message });
    }
  });

  // ========== СПИСОК БАНОВ ==========
  socket.on('admin get bans', async (callback) => {
    if (!socket.isAdmin) {
      if (typeof callback === 'function') callback({ ok: false, bans: [] });
      return;
    }
    try {
      const bans = await db.all(
        'SELECT username, reason, banned_by, banned_at FROM bans ORDER BY banned_at DESC'
      );
      if (typeof callback === 'function') callback({ ok: true, bans });
    } catch (e) {
      console.error('Get bans error:', e);
      if (typeof callback === 'function') callback({ ok: false, bans: [] });
    }
  });

  // ========== РЕАКЦИИ ==========
  socket.on('add reaction', async ({ messageId, emoji }, callback) => {
    if (!messageId || typeof emoji !== 'string') return;

    const ALLOWED = new Set(['👍','❤️','😂','😮','😢','🔥']);
    if (!ALLOWED.has(emoji)) return;

    const mid = parseInt(messageId, 10);
    if (!Number.isInteger(mid) || mid <= 0) return;

    try {
      const existing = await db.get(
        'SELECT emoji FROM reactions WHERE message_id = $1 AND username = $2',
        [mid, socket.username]
      );

      if (existing && existing.emoji === emoji) {
        await db.run('DELETE FROM reactions WHERE message_id = $1 AND username = $2', [mid, socket.username]);
      } else {
        await db.run(
          `INSERT INTO reactions (message_id, username, emoji) VALUES ($1, $2, $3) ON CONFLICT (message_id, username) DO UPDATE SET emoji = $3`,
          [mid, socket.username, emoji]
        );
      }

      const rows = await db.all(
        `SELECT emoji, COUNT(*) as count, array_agg(username) as users FROM reactions WHERE message_id = $1 GROUP BY emoji ORDER BY count DESC`,
        [mid]
      );

      io.emit('reactions updated', { messageId: mid, reactions: rows });
      if (typeof callback === 'function') callback({ ok: true });
    } catch (e) {
      console.error('Reaction error:', e);
      if (typeof callback === 'function') callback({ ok: false });
    }
  });

  // ========== ИСТОРИЯ ПРИ ПОДКЛЮЧЕНИИ ==========
  if (!socket.recovered) {
    try {
      const rows = await db.all(
        'SELECT id, content, username, msg_type, file_type, profile_data FROM messages ORDER BY id'
      );
      for (const row of rows) {
        let prf = {};
        try { if (row.profile_data) prf = JSON.parse(row.profile_data); } catch(e) {}

        const historyMsg = row.msg_type === 'file'
          ? { type: 'file', fileType: row.file_type || 'file', url: row.content, username: row.username, profile: prf }
          : { text: row.content, username: row.username, profile: prf };

        socket.emit('chat message', historyMsg, row.id);
      }

      const allReactions = await db.all(
        `SELECT message_id, emoji, COUNT(*) as count, array_agg(username) as users FROM reactions GROUP BY message_id, emoji`
      );
      if (allReactions.length > 0) {
        const byMsg = {};
        for (const r of allReactions) {
          if (!byMsg[r.message_id]) byMsg[r.message_id] = [];
          byMsg[r.message_id].push(r);
        }
        for (const [messageId, reactions] of Object.entries(byMsg)) {
          socket.emit('reactions updated', { messageId: parseInt(messageId, 10), reactions });
        }
      }
    } catch (err) {
      console.error('History error:', err);
    }
  }
});

const port = process.env.PORT || 3000;
server.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
