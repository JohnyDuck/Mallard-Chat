import express from 'express';
import { createServer } from 'node:http';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { Server } from 'socket.io';
import sqlite3 from 'sqlite3';
import { open } from 'sqlite';
import crypto from 'crypto';
import multer from 'multer';
import { v2 as cloudinary } from 'cloudinary';
import { Readable } from 'stream';

// ========== СПИСОК АДМИНИСТРАТОРОВ ==========
const ADMINS = new Set(['JohnyDuck', 'JohnyDuck_v2']);

function isAdmin(username) {
  return ADMINS.has(username);
}

const db = await open({
  filename: 'chat.db',
  driver: sqlite3.Database
});

await db.exec(`
  CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    client_offset TEXT UNIQUE,
    content TEXT,
    username TEXT,
    msg_type TEXT DEFAULT 'text',
    file_type TEXT,
    profile_data TEXT
  );
`);

await db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password_hash TEXT,
    token TEXT
  );
`);

await db.exec(`
  CREATE TABLE IF NOT EXISTS bans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    reason TEXT,
    banned_by TEXT,
    banned_at INTEGER DEFAULT (strftime('%s','now'))
  );
`);

// Добавляем колонки если их нет (для старых баз)
try { await db.exec(`ALTER TABLE messages ADD COLUMN msg_type TEXT DEFAULT 'text'`); } catch(e) {}
try { await db.exec(`ALTER TABLE messages ADD COLUMN file_type TEXT`); } catch(e) {}
try { await db.exec(`ALTER TABLE messages ADD COLUMN profile_data TEXT`); } catch(e) {}

// ========== НАСТРОЙКА CLOUDINARY ==========
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key:    process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

const app = express();
const server = createServer(app);

// ========== ЗАГРУЗКА ФАЙЛОВ ЧЕРЕЗ CLOUDINARY ==========
const upload = multer({ storage: multer.memoryStorage() });

function uploadToCloudinary(buffer, mimetype) {
  return new Promise((resolve, reject) => {
    const resourceType = mimetype.startsWith('video/') ? 'video' : 'image';
    const uploadStream = cloudinary.uploader.upload_stream(
      { resource_type: resourceType, folder: 'mallard_chat' },
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

  try {
    const result = await uploadToCloudinary(file.buffer, file.mimetype);

    const fileType = file.mimetype.startsWith('image/') ? 'image'
                   : file.mimetype.startsWith('video/') ? 'video'
                   : 'file';

    res.json({
      url: result.secure_url,
      fileType: fileType
    });
  } catch (err) {
    console.error('Ошибка Cloudinary:', err);
    res.status(500).json({ error: 'Ошибка загрузки файла' });
  }
});

// ========== ХЕШИРОВАНИЕ ПАРОЛЕЙ ==========
function hashPassword(password) {
  return crypto.createHash('sha256').update(password).digest('hex');
}

// ========== API РЕГИСТРАЦИИ ==========
app.post('/api/register', express.json(), async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password || password.length < 4) {
    return res.status(400).json({ error: 'Логин и пароль (мин 4 символа)' });
  }

  const existing = await db.get('SELECT id FROM users WHERE username = ?', username);
  if (existing) {
    return res.status(400).json({ error: 'Пользователь уже существует' });
  }

  const passwordHash = hashPassword(password);
  const token = crypto.randomBytes(32).toString('hex');

  await db.run('INSERT INTO users (username, password_hash, token) VALUES (?, ?, ?)',
    username, passwordHash, token);

  res.json({ token, username });
});

// ========== API ЛОГИНА ==========
app.post('/api/login', express.json(), async (req, res) => {
  const { username, password } = req.body;

  const user = await db.get('SELECT * FROM users WHERE username = ?', username);
  if (!user) {
    return res.status(400).json({ error: 'Пользователь не найден' });
  }

  if (user.password_hash !== hashPassword(password)) {
    return res.status(400).json({ error: 'Неверный пароль' });
  }

  const newToken = crypto.randomBytes(32).toString('hex');
  await db.run('UPDATE users SET token = ? WHERE id = ?', newToken, user.id);

  res.json({ token: newToken, username });
});

const io = new Server(server, {
  connectionStateRecovery: {}
});

// Проверка токена при подключении
io.use(async (socket, next) => {
  const token = socket.handshake.auth.token;
  if (!token) return next(new Error('Нет токена'));

  const user = await db.get('SELECT username FROM users WHERE token = ?', token);
  if (!user) return next(new Error('Неверный токен'));

  socket.username = user.username;
  socket.isAdmin  = isAdmin(user.username);
  next();
});

const __dirname = dirname(fileURLToPath(import.meta.url));

app.use(express.static('public'));
app.use('/public', express.static('public'));

app.get('/', (req, res) => {
  res.sendFile(join(__dirname, 'index.html'));
});

app.get('/login.html', (req, res) => {
  res.sendFile(join(__dirname, 'login.html'));
});

app.get('/register.html', (req, res) => {
  res.sendFile(join(__dirname, 'register.html'));
});

io.on('connection', async (socket) => {
  console.log(`Client connected: ${socket.username} (admin: ${socket.isAdmin})`);

  // Сообщаем клиенту его роль
  socket.emit('your role', { isAdmin: socket.isAdmin, username: socket.username });

  // ========== ОБРАБОТКА НОВОГО СООБЩЕНИЯ ==========
  socket.on('chat message', async (data, clientOffset, callback) => {

    // Проверяем бан
    const ban = await db.get('SELECT reason FROM bans WHERE username = ?', socket.username);
    if (ban) {
      socket.emit('banned', { reason: ban.reason });
      if (typeof callback === 'function') callback();
      return;
    }

    let msgText, msgUsername, msgType, fileType, profileData;

    if (data.type === 'file') {
      msgText     = data.url;
      msgUsername = data.username;
      msgType     = 'file';
      fileType    = data.fileType;
    } else {
      msgText     = data.text;
      msgUsername = data.username || 'Anonymous';
      msgType     = 'text';
      fileType    = null;
    }

    profileData = data.profile ? JSON.stringify(data.profile) : null;

    console.log(`Message from ${msgUsername}: ${msgText}`);

    let result;
    try {
      result = await db.run(
        'INSERT INTO messages (content, client_offset, username, msg_type, file_type, profile_data) VALUES (?, ?, ?, ?, ?, ?)',
        msgText, clientOffset || null, msgUsername, msgType, fileType, profileData
      );
    } catch (e) {
      if (typeof callback === 'function') callback();
      return;
    }

    const emitMsg = data.type === 'file'
      ? { type: 'file', fileType: data.fileType, url: data.url, username: msgUsername, profile: data.profile || {} }
      : { text: msgText, username: msgUsername, profile: data.profile || {} };

    io.emit('chat message', emitMsg, result.lastID);

    if (typeof callback === 'function') callback();
  });

  // ========== УДАЛЕНИЕ СООБЩЕНИЙ ==========
  socket.on('delete messages', async (ids, callback) => {
    if (!Array.isArray(ids) || ids.length === 0) return;
    try {
      const placeholders = ids.map(() => '?').join(',');

      let validIds;
      if (socket.isAdmin) {
        // Админ может удалять любые сообщения
        const rows = await db.all(
          `SELECT id FROM messages WHERE id IN (${placeholders})`,
          ...ids
        );
        validIds = rows.map(r => r.id);
      } else {
        // Обычный пользователь — только свои
        const rows = await db.all(
          `SELECT id FROM messages WHERE id IN (${placeholders}) AND username = ?`,
          ...ids, socket.username
        );
        validIds = rows.map(r => r.id);
      }

      if (validIds.length === 0) return;
      const ph2 = validIds.map(() => '?').join(',');
      await db.run(`DELETE FROM messages WHERE id IN (${ph2})`, ...validIds);
      io.emit('messages deleted', validIds);
      if (typeof callback === 'function') callback({ ok: true });
    } catch (e) {
      console.error('Delete error:', e);
      if (typeof callback === 'function') callback({ ok: false });
    }
  });

  // ========== БАН ПОЛЬЗОВАТЕЛЯ (только для админов) ==========
  socket.on('admin ban', async ({ targetUsername, reason }, callback) => {
    if (!socket.isAdmin) {
      if (typeof callback === 'function') callback({ ok: false, error: 'not admin' });
      return;
    }
    if (!targetUsername) {
      if (typeof callback === 'function') callback({ ok: false, error: 'no target' });
      return;
    }

    try {
      await db.run(
        'INSERT OR REPLACE INTO bans (username, reason, banned_by) VALUES (?, ?, ?)',
        targetUsername, reason || 'Нарушение правил', socket.username
      );

      // Кикаем все активные сокеты забаненного
      for (const [, s] of io.sockets.sockets) {
        if (s.username === targetUsername) {
          s.emit('banned', { reason: reason || 'Нарушение правил' });
        }
      }

      // Уведомляем всех о бане (для UI)
      io.emit('user banned', { username: targetUsername });

      console.log(`[ADMIN] ${socket.username} banned ${targetUsername}: ${reason}`);
      if (typeof callback === 'function') callback({ ok: true });
    } catch (e) {
      console.error('Ban error:', e);
      if (typeof callback === 'function') callback({ ok: false, error: e.message });
    }
  });

  // ========== РАЗБАН (только для админов) ==========
  socket.on('admin unban', async ({ targetUsername }, callback) => {
    if (!socket.isAdmin) {
      if (typeof callback === 'function') callback({ ok: false, error: 'not admin' });
      return;
    }
    try {
      await db.run('DELETE FROM bans WHERE username = ?', targetUsername);
      io.emit('user unbanned', { username: targetUsername });
      console.log(`[ADMIN] ${socket.username} unbanned ${targetUsername}`);
      if (typeof callback === 'function') callback({ ok: true });
    } catch (e) {
      if (typeof callback === 'function') callback({ ok: false, error: e.message });
    }
  });

  // ========== СПИСОК БАНОВ (только для админов) ==========
  socket.on('admin get bans', async (callback) => {
    if (!socket.isAdmin) {
      if (typeof callback === 'function') callback({ ok: false, bans: [] });
      return;
    }
    try {
      const bans = await db.all('SELECT username, reason, banned_by, banned_at FROM bans ORDER BY banned_at DESC');
      if (typeof callback === 'function') callback({ ok: true, bans });
    } catch (e) {
      console.error('Get bans error:', e);
      if (typeof callback === 'function') callback({ ok: false, bans: [] });
    }
  });

  // ========== ИСТОРИЯ ПРИ ПЕРЕЗАГРУЗКЕ ==========
  if (!socket.recovered) {
    try {
      const rows = await db.all('SELECT id, content, username, msg_type, file_type, profile_data FROM messages ORDER BY id');
      for (const row of rows) {
        const historyUsername = row.username || 'System';
        let prf = {};
        try { if (row.profile_data) prf = JSON.parse(row.profile_data); } catch(e) {}
        let historyMsg;

        if (row.msg_type === 'file') {
          historyMsg = { type: 'file', fileType: row.file_type || 'file', url: row.content, username: historyUsername, profile: prf };
        } else {
          historyMsg = { text: row.content, username: historyUsername, profile: prf };
        }

        socket.emit('chat message', historyMsg, row.id);
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
