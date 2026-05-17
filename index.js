import express from 'express';
import { createServer } from 'node:http';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { Server } from 'socket.io';
import sqlite3 from 'sqlite3';
import { open } from 'sqlite';
import { availableParallelism } from 'node:os';
import cluster from 'node:cluster';
import { createAdapter, setupPrimary } from '@socket.io/cluster-adapter';
import crypto from 'crypto';
import multer from 'multer';
import { v2 as cloudinary } from 'cloudinary';
import { Readable } from 'stream';

if (cluster.isPrimary) {
  const numCPUs = availableParallelism();
  for (let i = 0; i < numCPUs; i++) {
    cluster.fork({
      PORT: 3000 + i
    });
  }
  setupPrimary();
} else {
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
      file_type TEXT
    );
  `);

  // Добавляем колонки если их нет (для старых баз)
  try { await db.exec(`ALTER TABLE messages ADD COLUMN msg_type TEXT DEFAULT 'text'`); } catch(e) {}
  try { await db.exec(`ALTER TABLE messages ADD COLUMN file_type TEXT`); } catch(e) {}

  // Таблица пользователей
  await db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE,
      password_hash TEXT,
      token TEXT
    );
  `);

  // ========== НАСТРОЙКА CLOUDINARY ==========
  cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key:    process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET,
  });

  const app = express();
  const server = createServer(app);

  // ========== ЗАГРУЗКА ФАЙЛОВ ЧЕРЕЗ CLOUDINARY ==========
  // Multer хранит файл в памяти (не на диск — диск на Render эфемерный)
  const upload = multer({ storage: multer.memoryStorage() });

  // Загружаем буфер в Cloudinary через stream
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

  // API загрузки файла
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
    connectionStateRecovery: {},
    adapter: createAdapter()
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

  // Раздаём статические файлы
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
      let msgText, msgUsername, msgType, fileType;

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

      console.log(`Message from ${msgUsername}: ${msgText}`);

      let result;
      try {
        result = await db.run(
          'INSERT INTO messages (content, client_offset, username, msg_type, file_type) VALUES (?, ?, ?, ?, ?)',
          msgText, clientOffset, msgUsername, msgType, fileType
        );
      } catch (e) {
        if (e.errno === 19 && typeof callback === 'function') {
          callback();
        }
        return;
      }

      if (data.type === 'file') {
        io.emit('chat message', {
          type: 'file',
          fileType: data.fileType,
          url: data.url,
          username: msgUsername
        }, result.lastID);
      } else {
        io.emit('chat message', { text: msgText, username: msgUsername }, result.lastID);
      }

      if (typeof callback === 'function') {
        callback();
      }
    });

    // ========== ОТПРАВКА ИСТОРИИ ПРИ ПЕРЕЗАГРУЗКЕ ==========
    if (!socket.recovered) {
      try {
        const history = await db.all('SELECT id, content, username, msg_type, file_type FROM messages ORDER BY id');
        for (const row of history) {
          const historyUsername = row.username || 'System';
          let historyMsg;

          // Используем сохранённый тип — больше не угадываем по расширению
          if (row.msg_type === 'file') {
            historyMsg = {
              type: 'file',
              fileType: row.file_type || 'file',
              url: row.content,
              username: historyUsername
            };
          } else {
            historyMsg = { text: row.content, username: historyUsername };
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
}
