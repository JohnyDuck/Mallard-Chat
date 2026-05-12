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
      content TEXT
    );
  `);

  const app = express();
  const server = createServer(app);
  const io = new Server(server, {
    connectionStateRecovery: {},
    adapter: createAdapter()
  });

  const __dirname = dirname(fileURLToPath(import.meta.url));

  // Раздаём статические файлы
  app.use(express.static('public'));
  app.use('/public', express.static('public'));
  
  app.get('/', (req, res) => {
    res.sendFile(join(__dirname, 'index.html'));
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
        result = await db.run('INSERT INTO messages (content, client_offset) VALUES (?, ?)', msgText, clientOffset);
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
        const history = await db.all('SELECT id, content FROM messages ORDER BY id');
        console.log(`Sending ${history.length} history messages`);
        for (const row of history) {
          socket.emit('chat message', { text: row.content, username: 'System' }, row.id);
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