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

// УБРАЛИ CLUSTER — он был причиной дублирования сообщений (8 воркеров × 1 emit = 8 копий)
// На бесплатном Render всё равно 1 CPU, так что потери нет

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
  console.log('New client connected');

  // ========== ОБРАБОТКА НОВОГО СООБЩЕНИЯ ==========
  socket.on('chat message', async (data, clientOffset, callback) => {
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
