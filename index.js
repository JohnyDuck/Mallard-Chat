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
    avatar_url TEXT,
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

await db.run(`CREATE INDEX IF NOT EXISTS idx_users_token ON users(token)`);
await db.run(`CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)`);
await db.run(`CREATE INDEX IF NOT EXISTS idx_bans_username ON bans(username)`);

// ========== РЕАКЦИИ ==========
await db.run(`
  CREATE TABLE IF NOT EXISTS reactions (
    message_id INTEGER NOT NULL,
    username   TEXT    NOT NULL,
    emoji      TEXT    NOT NULL,
    PRIMARY KEY (message_id, username)
  )
`);
await db.run(`CREATE INDEX IF NOT EXISTS idx_reactions_msg ON reactions(message_id)`);

async function getReactionsForMessages(messageIds) {
  if (!messageIds || messageIds.length === 0) return {};
  const ph = messageIds.map((_, i) => `$${i+1}`).join(',');
  const rows = await db.all(
    `SELECT message_id, emoji, username FROM reactions WHERE message_id IN (${ph})`,
    messageIds
  );
  const result = {};
  for (const r of rows) {
    if (!result[r.message_id]) result[r.message_id] = {};
    if (!result[r.message_id][r.emoji]) result[r.message_id][r.emoji] = [];
    result[r.message_id][r.emoji].push(r.username);
  }
  return result;
}

async function getReactionsForOne(messageId) {
  const rows = await db.all(
    'SELECT emoji, username FROM reactions WHERE message_id = $1',
    [messageId]
  );
  const result = {};
  for (const r of rows) {
    if (!result[r.emoji]) result[r.emoji] = [];
    result[r.emoji].push(r.username);
  }
  return result;
}

// ========== НАСТРОЙКА CLOUDINARY ==========
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key:    process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

const app = express();
const server = createServer(app);

// ========== SECURITY HEADERS ==========
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc:  ["'self'", "'unsafe-inline'", "https://cdn.socket.io"],
      styleSrc:   ["'self'", "'unsafe-inline'"],
      imgSrc:     ["'self'", "data:", "https://res.cloudinary.com", "blob:"],
      mediaSrc:   ["'self'", "https://res.cloudinary.com", "blob:"],
      connectSrc: ["'self'", "wss:", "ws:"],
    },
  },
  crossOriginEmbedderPolicy: false,
}));

// ========== RATE LIMITING ==========
const authLimiter = rateLimit({
  windowMs: 1 * 60 * 1000,
  max: 5,
  message: { error: 'Слишком много попыток. Подождите 1 минуту.' },
});

const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 100,
  message: { error: 'Слишком много запросов.' },
});

app.use('/api/', apiLimiter);
app.use('/api/login', authLimiter);
app.use('/api/register', authLimiter);

// ========== ЗАГРУЗКА ФАЙЛОВ ==========
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 50 * 1024 * 1024 },
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

// Старый эндпоинт для загрузки файлов в чат
app.post('/api/upload', upload.single('file'), async (req, res) => {
  const file = req.file;
  if (!file) return res.status(400).json({ error: 'Нет файла' });

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

// ========== НОВЫЙ ЭНДПОИНТ ДЛЯ ЗАГРУЗКИ АВАТАРА ==========
app.post('/api/upload-avatar', upload.single('avatar'), async (req, res) => {
  const file = req.file;
  if (!file) return res.status(400).json({ error: 'Нет файла' });

  const authHeader = req.headers['authorization'] || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Не авторизован' });

  try {
    const user = await db.get('SELECT id, username FROM users WHERE token = $1', [token]);
    if (!user) return res.status(401).json({ error: 'Неверный токен' });

    // Аватарки загружаем в отдельную папку avatars
    const result = await new Promise((resolve, reject) => {
      const uploadStream = cloudinary.uploader.upload_stream(
        { 
          folder: `mallard_chat/avatars/${user.username}`,
          transformation: [
            { width: 200, height: 200, crop: 'limit' },
            { quality: 'auto' }
          ]
        },
        (error, result) => {
          if (error) reject(error);
          else resolve(result);
        }
      );
      Readable.from(file.buffer).pipe(uploadStream);
    });

    // Сохраняем URL аватара в БД
    await db.run(
      'UPDATE users SET avatar_url = $1 WHERE id = $2',
      [result.secure_url, user.id]
    );

    res.json({ avatar_url: result.secure_url });
  } catch (err) {
    console.error('Ошибка загрузки аватара:', err);
    res.status(500).json({ error: 'Ошибка загрузки аватара' });
  }
});

// ========== ПОЛУЧИТЬ ДАННЫЕ ПОЛЬЗОВАТЕЛЯ (включая аватар) ==========
app.get('/api/user/:username', async (req, res) => {
  const { username } = req.params;
  try {
    const user = await db.get(
      'SELECT username, avatar_url, created_at FROM users WHERE username = $1',
      [username]
    );
    if (!user) return res.status(404).json({ error: 'Пользователь не найден' });
    res.json(user);
  } catch (err) {
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// ========== ХЕШИРОВАНИЕ ПАРОЛЕЙ ==========
const BCRYPT_ROUNDS = 12;

async function hashPassword(password) {
  return bcrypt.hash(password, BCRYPT_ROUNDS);
}

async function verifyPassword(password, hash) {
  return bcrypt.compare(password, hash);
}

function generateToken() {
  return crypto.randomBytes(48).toString('hex');
}

function sanitizeUsername(username) {
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

    if (!user) {
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

    res.json({ 
      token: newToken, 
      username: user.username,
      avatar_url: user.avatar_url || null
    });
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
    const user = await db.get('SELECT username, avatar_url FROM users WHERE token = $1', [token]);
    if (!user) return res.status(401).json({ valid: false });
    res.json({ valid: true, username: user.username, avatar_url: user.avatar_url });
  } catch (err) {
    res.status(500).json({ valid: false });
  }
});

// ========== SOCKET.IO ==========
const io = new Server(server, {
  connectionStateRecovery: {},
  maxHttpBufferSize: 1e6,
});

io.use(async (socket, next) => {
  const token = socket.handshake.auth.token;
  if (!token || typeof token !== 'string' || token.length > 200) {
    return next(new Error('Нет токена'));
  }

  try {
    const user = await db.get('SELECT username, avatar_url FROM users WHERE token = $1', [token]);
    if (!user) return next(new Error('Неверный токен'));

    socket.username = user.username;
    socket.avatar_url = user.avatar_url;
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

  socket.emit('your role', { 
    isAdmin: socket.isAdmin, 
    username: socket.username,
    avatar_url: socket.avatar_url 
  });

  // Функция для получения актуального профиля (аватар может обновиться)
  async function getUserProfile(username) {
    const user = await db.get('SELECT avatar_url FROM users WHERE username = $1', [username]);
    return {
      username: username,
      avatar_url: user?.avatar_url || null
    };
  }

  // ========== ОБРАБОТКА НОВОГО СООБЩЕНИЯ ==========
  socket.on('chat message', async (data, clientOffset, callback) => {
    try {
      const ban = await db.get('SELECT reason FROM bans WHERE username = $1', [socket.username]);
      if (ban) {
        socket.emit('banned', { reason: ban.reason });
        if (typeof callback === 'function') callback();
        return;
      }

      let msgText, msgUsername, msgType, fileType;
      const userProfile = await getUserProfile(socket.username);

      if (data.type === 'file') {
        msgText     = data.url;
        msgUsername = socket.username;
        msgType     = 'file';
        fileType    = data.fileType;
      } else {
        if (typeof data.text !== 'string') {
          if (typeof callback === 'function') callback();
          return;
        }
        msgText     = data.text.substring(0, 4000);
        msgUsername = socket.username;
        msgType     = 'text';
        fileType    = null;
      }

      const profileData = JSON.stringify(userProfile);

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
        ? { type: 'file', fileType: data.fileType, url: data.url, username: msgUsername, profile: userProfile }
        : { text: msgText, username: msgUsername, profile: userProfile };

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
  socket.on('react', async ({ messageId, emoji }, callback) => {
    if (!messageId || !emoji || typeof emoji !== 'string' || emoji.length > 10) {
      if (typeof callback === 'function') callback({ ok: false });
      return;
    }
    const ban = await db.get('SELECT id FROM bans WHERE username = $1', [socket.username]);
    if (ban) { if (typeof callback === 'function') callback({ ok: false }); return; }

    try {
      const existing = await db.get(
        'SELECT emoji FROM reactions WHERE message_id = $1 AND username = $2',
        [messageId, socket.username]
      );

      if (existing && existing.emoji === emoji) {
        await db.run(
          'DELETE FROM reactions WHERE message_id = $1 AND username = $2',
          [messageId, socket.username]
        );
      } else {
        await db.run(
          'INSERT INTO reactions (message_id, username, emoji) VALUES ($1, $2, $3) ON CONFLICT (message_id, username) DO UPDATE SET emoji = $3',
          [messageId, socket.username, emoji]
        );
      }

      const reactions = await getReactionsForOne(messageId);
      io.emit('reactions update', { messageId, reactions });
      if (typeof callback === 'function') callback({ ok: true });
    } catch (err) {
      console.error('React error:', err);
      if (typeof callback === 'function') callback({ ok: false });
    }
  });

  // ========== ИСТОРИЯ ПРИ ПОДКЛЮЧЕНИИ ==========
  if (!socket.recovered) {
    try {
      const rows = await db.all(
        'SELECT id, content, username, msg_type, file_type, profile_data FROM messages ORDER BY id'
      );
      const messageIds = rows.map(r => r.id);
      const allReactions = await getReactionsForMessages(messageIds);

      for (const row of rows) {
        let prf = {};
        try { if (row.profile_data) prf = JSON.parse(row.profile_data); } catch(e) {}

        const historyMsg = row.msg_type === 'file'
          ? { type: 'file', fileType: row.file_type || 'file', url: row.content, username: row.username, profile: prf }
          : { text: row.content, username: row.username, profile: prf };

        socket.emit('chat message', historyMsg, row.id);

        const reactions = allReactions[row.id];
        if (reactions && Object.keys(reactions).length > 0) {
          socket.emit('reactions update', { messageId: row.id, reactions });
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