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
      username TEXT
    );
  `);

  // Таблица пользователей
  await db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE,
      password_hash TEXT,
      token TEXT
    );
  `);

  const app = express();
  const server = createServer(app);
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

  // Отдаём страницу входа
  app.get('/login.html', (req, res) => {
    res.sendFile(join(__dirname, 'login.html'));
  });

  // Отдаём страницу регистрации
  app.get('/register.html', (req, res) => {
    res.sendFile(join(__dirname, 'register.html'));
  });

  io.on('connection', async (socket) => {
    console.log('New client connected');

    // ========== ОБРАБОТКА НОВОГО СООБЩЕНИЯ ==========
    socket.on('chat message', async (data, clientOffset, callback) => {
      const msgText = data.text;
      const msgUsername = data.username || 'Anonymous';
      
      console.log(`Message from ${msgUsername}: ${msgText}`);
      
      let result;
      try {
        result = await db.run('INSERT INTO messages (content, client_offset, username) VALUES (?, ?, ?)', msgText, clientOffset, msgUsername);
      } catch (e) {
        if (e.errno === 19) {
          callback();
        }
        return;
      }
      
      io.emit('chat message', { text: msgText, username: msgUsername }, result.lastID);
      callback();
    });

    // ========== ОТПРАВКА ИСТОРИИ ПРИ ПЕРЕЗАГРУЗКЕ ==========
    if (!socket.recovered) {
      try {
        const history = await db.all('SELECT id, content, username FROM messages ORDER BY id');
        for (const row of history) {
          const historyUsername = row.username || 'System'; // если старые записи без имени
          socket.emit('chat message', { text: row.content, username: historyUsername }, row.id);
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