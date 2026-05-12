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
  app.use(express.static('public'));
  app.use('/public', express.static('public'));
  const io = new Server(server, {
    connectionStateRecovery: {},
    adapter: createAdapter()
  });

  const __dirname = dirname(fileURLToPath(import.meta.url));

  app.get('/', (req, res) => {
    res.sendFile(join(__dirname, 'index.html'));
  });

  io.on('connection', async (socket) => {
    socket.on('chat message', async (data, clientOffset, callback) => {
  let result;
  // Извлекаем текст сообщения и имя пользователя
  const msgText = data.text;
  const msgUsername = data.username;

  try {
    // Сохраняем в базу данных (можно сохранять и имя, но для простоты сохраняем только текст)
    result = await db.run('INSERT INTO messages (content, client_offset) VALUES (?, ?)', msgText, clientOffset);
  } catch (e) {
    if (e.errno === 19 /* SQLITE_CONSTRAINT */ ) {
      callback();
    } else {
      // nothing to do, just let the client retry
    }
    return;
  }
  // Отправляем всем объект с текстом и именем
  io.emit('chat message', { text: msgText, username: msgUsername }, result.lastID);
  callback();
});

    if (!socket.recovered) {
      try {
        await db.each('SELECT id, content FROM messages WHERE id > ?',
          [socket.handshake.auth.serverOffset || 0],
          (_err, row) => {
            socket.emit('chat message', row.content, row.id);
          }
        )
      } catch (e) {
        // something went wrong
      }
    }
  });

  const port = process.env.PORT;

  server.listen(port, () => {
    console.log(`server running at http://localhost:${port}`);
  });
}
