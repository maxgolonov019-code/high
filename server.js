const express = require("express");
const http = require("http");
const path = require("path");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const { Pool } = require("pg");
const { Server } = require("socket.io");

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const PORT = process.env.PORT || 3000;
const DATABASE_URL = process.env.DATABASE_URL;
const JWT_SECRET = process.env.JWT_SECRET;

if (!DATABASE_URL || !JWT_SECRET) {
  throw new Error("Укажи DATABASE_URL и JWT_SECRET в Render.");
}

app.set("trust proxy", 1);
app.use(express.json({ limit: "32kb" }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public")));

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: process.env.NODE_ENV === "production"
    ? { rejectUnauthorized: false }
    : false,
  max: 10
});

const COOKIE_NAME = "high_token";

const cookieOptions = {
  httpOnly: true,
  secure: process.env.NODE_ENV === "production",
  sameSite: "lax",
  path: "/",
  maxAge: 7 * 24 * 60 * 60 * 1000
};

async function initializeDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id BIGSERIAL PRIMARY KEY,
      username VARCHAR(24) NOT NULL,
      username_lower VARCHAR(24) UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS messages (
      id BIGSERIAL PRIMARY KEY,
      sender_id BIGINT NOT NULL REFERENCES users(id),
      receiver_id BIGINT NOT NULL REFERENCES users(id),
      body VARCHAR(4000) NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS messages_chat_idx
    ON messages(sender_id, receiver_id, id);

    CREATE INDEX IF NOT EXISTS messages_receiver_idx
    ON messages(receiver_id, id);
  `);

  console.log("High: база данных готова");
}

function createToken(user) {
  return jwt.sign(
    {
      id: String(user.id),
      username: user.username
    },
    JWT_SECRET,
    { expiresIn: "7d" }
  );
}

function readToken(token) {
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch {
    return null;
  }
}

function requireAuth(req, res, next) {
  const token = req.cookies[COOKIE_NAME];
  const user = token && readToken(token);

  if (!user) {
    return res.status(401).json({
      error: "Войди в аккаунт."
    });
  }

  req.user = user;
  next();
}

function validUsername(value) {
  return typeof value === "string" &&
    /^[a-zA-Z0-9_]{3,24}$/.test(value);
}

// Регистрация
app.post("/api/register", async (req, res) => {
  try {
    const username = req.body.username?.trim();
    const password = req.body.password;

    if (!validUsername(username)) {
      return res.status(400).json({
        error: "Имя: 3–24 символа, только латиница, цифры и _."
      });
    }

    if (
      typeof password !== "string" ||
      password.length < 8 ||
      password.length > 128
    ) {
      return res.status(400).json({
        error: "Пароль должен содержать от 8 до 128 символов."
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const result = await pool.query(
      `INSERT INTO users
       (username, username_lower, password_hash)
       VALUES ($1, $2, $3)
       RETURNING id, username`,
      [username, username.toLowerCase(), passwordHash]
    );

    const user = result.rows[0];

    res.cookie(COOKIE_NAME, createToken(user), cookieOptions);
    res.status(201).json({ user });
  } catch (error) {
    if (error.code === "23505") {
      return res.status(409).json({
        error: "Такое имя уже занято."
      });
    }

    console.error(error);
    res.status(500).json({ error: "Ошибка регистрации." });
  }
});

// Вход
app.post("/api/login", async (req, res) => {
  try {
    const username = req.body.username?.trim().toLowerCase();
    const password = req.body.password;

    if (
      typeof username !== "string" ||
      typeof password !== "string"
    ) {
      return res.status(400).json({
        error: "Заполни имя и пароль."
      });
    }

    const result = await pool.query(
      `SELECT id, username, password_hash
       FROM users WHERE username_lower = $1`,
      [username]
    );

    const user = result.rows[0];

    if (!user || !(await bcrypt.compare(
      password,
      user.password_hash
    ))) {
      return res.status(401).json({
        error: "Неверное имя или пароль."
      });
    }

    res.cookie(COOKIE_NAME, createToken(user), cookieOptions);

    res.json({
      user: {
        id: String(user.id),
        username: user.username
      }
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Ошибка входа." });
  }
});

// Текущий аккаунт
app.get("/api/me", requireAuth, async (req, res) => {
  res.json({
    user: {
      id: req.user.id,
      username: req.user.username
    }
  });
});

// Выход
app.post("/api/logout", (req, res) => {
  res.clearCookie(COOKIE_NAME, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    path: "/"
  });

  res.json({ ok: true });
});

// Поиск пользователей
app.get("/api/users", requireAuth, async (req, res) => {
  try {
    const q = String(req.query.q || "").trim();

    if (q.length < 2) {
      return res.json({ users: [] });
    }

    const result = await pool.query(
      `SELECT id, username
       FROM users
       WHERE username_lower LIKE $1
       AND id <> $2
       ORDER BY username_lower
       LIMIT 30`,
      [
        q.toLowerCase().replace(/[\\%_]/g, "\\$&") + "%",
        req.user.id
      ]
    );

    res.json({
      users: result.rows.map(user => ({
        id: String(user.id),
        username: user.username
      }))
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Ошибка поиска." });
  }
});

// История переписки
app.get(
  "/api/messages/:userId",
  requireAuth,
  async (req, res) => {
    try {
      const otherId = req.params.userId;

      if (!/^\d+$/.test(otherId) || otherId === req.user.id) {
        return res.status(400).json({
          error: "Некорректный собеседник."
        });
      }

      const result = await pool.query(
        `SELECT id, sender_id, receiver_id, body, created_at
         FROM (
           SELECT *
           FROM messages
           WHERE (
             sender_id = $1 AND receiver_id = $2
           ) OR (
             sender_id = $2 AND receiver_id = $1
           )
           ORDER BY id DESC
           LIMIT 100
         ) recent
         ORDER BY id ASC`,
        [req.user.id, otherId]
      );

      res.json({
        messages: result.rows.map(message => ({
          id: String(message.id),
          senderId: String(message.sender_id),
          receiverId: String(message.receiver_id),
          body: message.body,
          createdAt: message.created_at
        }))
      });
    } catch (error) {
      console.error(error);
      res.status(500).json({ error: "Ошибка загрузки чата." });
    }
  }
);

// Проверяем, что собеседник существует
async function userExists(id) {
  const result = await pool.query(
    "SELECT id FROM users WHERE id = $1",
    [id]
  );

  return result.rowCount > 0;
}

// WebSocket: авторизация по HttpOnly cookie
io.use((socket, next) => {
  const cookieHeader = socket.handshake.headers.cookie || "";
  const match = cookieHeader.match(
    /(?:^|;\s*)high_token=([^;]+)/
  );

  let token;

  try {
    token = match ? decodeURIComponent(match[1]) : null;
  } catch {
    return next(new Error("Неверная cookie."));
  }

  const user = token && readToken(token);

  if (!user) {
    return next(new Error("Требуется вход."));
  }

  socket.user = user;
  next();
});

io.on("connection", socket => {
  const userId = socket.user.id;

  // Все вкладки одного аккаунта получают события
  socket.join(`user:${userId}`);

  // Отправка сообщения
  socket.on("message:send", async (data, callback) => {
    const reply = typeof callback === "function"
      ? callback
      : () => {};

    try {
      const receiverId = String(data?.receiverId || "");
      const body = typeof data?.body === "string"
        ? data.body.trim()
        : "";

      if (
        !/^\d+$/.test(receiverId) ||
        receiverId === userId ||
        !body ||
        body.length > 4000
      ) {
        return reply({
          error: "Некорректное сообщение."
        });
      }

      if (!(await userExists(receiverId))) {
        return reply({
          error: "Пользователь не найден."
        });
      }

      const result = await pool.query(
        `INSERT INTO messages
         (sender_id, receiver_id, body)
         VALUES ($1, $2, $3)
         RETURNING id, sender_id, receiver_id, body, created_at`,
        [userId, receiverId, body]
      );

      const row = result.rows[0];

      const message = {
        id: String(row.id),
        senderId: String(row.sender_id),
        receiverId: String(row.receiver_id),
        body: row.body,
        createdAt: row.created_at
      };

      io.to(`user:${userId}`)
        .to(`user:${receiverId}`)
        .emit("message:new", message);

      reply({ ok: true, message });
    } catch (error) {
      console.error(error);
      reply({ error: "Не удалось отправить сообщение." });
    }
  });

  // Сигнализация WebRTC.
  // Сами аудио и видео идут напрямую между устройствами.
  socket.on("call:signal", async data => {
    const to = String(data?.to || "");
    const type = data?.type;
    const payload = data?.payload;

    const allowed = [
      "offer",
      "answer",
      "ice-candidate",
      "incoming",
      "accepted",
      "declined",
      "ended"
    ];

    if (
      !/^\d+$/.test(to) ||
      to === userId ||
      !allowed.includes(type)
    ) {
      return;
    }

    if (
      payload &&
      JSON.stringify(payload).length > 100000
    ) {
      return;
    }

    if (!(await userExists(to))) {
      return;
    }

    io.to(`user:${to}`).emit("call:signal", {
      from: userId,
      fromUsername: socket.user.username,
      type,
      payload: payload ?? null
    });
  });

  socket.on("disconnect", () => {
    console.log("High: отключён пользователь", userId);
  });
});

async function start() {
  await initializeDatabase();

  server.listen(PORT, "0.0.0.0", () => {
    console.log(`High запущен на порту ${PORT}`);
  });
}

start().catch(error => {
  console.error("Не удалось запустить High:", error);
  process.exit(1);
});
