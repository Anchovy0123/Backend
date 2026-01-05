// index.js
require("dotenv").config();

const express = require("express");
const mysql = require("mysql2/promise");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");

const verifyToken = require("./middleware/auth");
const { swaggerUi, specs } = require("./swagger");

const app = express();
app.use(cors());
app.use(express.json());

// ✅ SECRET_KEY ให้ชัดเจน
const SECRET_KEY = process.env.SECRET_KEY || process.env.JWT_SECRET;
if (!SECRET_KEY) {
  console.warn("[WARN] Missing SECRET_KEY/JWT_SECRET in .env");
}

// =========================
//  DB Pool
// =========================
const db = mysql.createPool({
  host: process.env.DB_HOST,
  port: Number(process.env.DB_PORT || 3306),
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});

// =========================
//  Init Schema (อย่างน้อย tbl_users)
// =========================
async function initializeSchema() {
  const createUsersTableSQL = `
    CREATE TABLE IF NOT EXISTS tbl_users (
      id INT AUTO_INCREMENT PRIMARY KEY,
      firstname VARCHAR(100),
      fullname VARCHAR(255),
      lastname VARCHAR(100),
      username VARCHAR(100) NOT NULL UNIQUE,
      password VARCHAR(255) NOT NULL,
      status VARCHAR(20) NOT NULL DEFAULT 'active',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
  `;

  await db.query(createUsersTableSQL);
  console.log("tbl_users table is ready");
}

// =========================
//  Health Check
// =========================
app.get("/ping", async (req, res) => {
  try {
    const [rows] = await db.query("SELECT NOW() AS now");
    res.json({ status: "ok", time: rows[0].now });
  } catch (err) {
    console.error("GET /ping error:", err);
    res.status(500).json({ error: "Database error" });
  }
});

// =========================
//  USERS (tbl_users)
// =========================

// CREATE user
app.post(["/users", "/api/users"], async (req, res) => {
  const firstname = String(req.body?.firstname ?? "").trim();
  const fullname = String(req.body?.fullname ?? "").trim();
  const lastname = String(req.body?.lastname ?? "").trim();
  const username = String(req.body?.username ?? "").trim();
  const password = String(req.body?.password ?? "");

  try {
    if (!username) return res.status(400).json({ error: "Username is required" });
    if (!password) return res.status(400).json({ error: "Password is required" });

    const [dupes] = await db.query(
      "SELECT id FROM tbl_users WHERE username = ? LIMIT 1",
      [username]
    );
    if (dupes.length > 0) return res.status(409).json({ error: "Username already exists" });

    const hashedPassword = await bcrypt.hash(password, 10);

    const [result] = await db.query(
      `INSERT INTO tbl_users (firstname, fullname, lastname, username, password)
       VALUES (?, ?, ?, ?, ?)`,
      [firstname || null, fullname || null, lastname || null, username, hashedPassword]
    );

    return res.status(201).json({
      id: result.insertId,
      firstname: firstname || "",
      fullname: fullname || "",
      lastname: lastname || "",
      username,
    });
  } catch (err) {
    console.error("POST /users error:", err);
    return res.status(500).json({
      error: "Insert failed",
      code: err.code,
      sqlMessage: err.sqlMessage,
    });
  }
});

// GET users (protected)
app.get(["/users", "/api/users"], verifyToken, async (req, res) => {
  try {
    const [rows] = await db.query(
      "SELECT id, firstname, fullname, lastname, username, status, created_at FROM tbl_users ORDER BY id DESC"
    );
    res.json(rows);
  } catch (err) {
    console.error("GET /users error:", err);
    res.status(500).json({ error: "Query failed", code: err.code, sqlMessage: err.sqlMessage });
  }
});

// GET user by id (protected)
app.get(["/users/:id", "/api/users/:id"], verifyToken, async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: "Invalid id" });

  try {
    const [rows] = await db.query(
      "SELECT id, firstname, fullname, lastname, username, status, created_at FROM tbl_users WHERE id = ? LIMIT 1",
      [id]
    );
    if (rows.length === 0) return res.status(404).json({ message: "User not found" });
    res.json(rows[0]);
  } catch (err) {
    console.error("GET /users/:id error:", err);
    res.status(500).json({ error: "Query failed", code: err.code, sqlMessage: err.sqlMessage });
  }
});

// LOGIN users
app.post(["/login", "/api/login"], async (req, res) => {
  try {
    const username = String(req.body?.username ?? "").trim();
    const password = String(req.body?.password ?? "");

    if (!username || !password) {
      return res.status(400).json({ error: "username/password is required" });
    }

    const [rows] = await db.query(
      "SELECT id, firstname, fullname, lastname, username, password, status FROM tbl_users WHERE username = ? LIMIT 1",
      [username]
    );
    if (rows.length === 0) return res.status(401).json({ error: "User not found" });

    const user = rows[0];
    const dbPass = String(user.password ?? "");

    let passOK = false;
    if (dbPass.startsWith("$2")) {
      passOK = await bcrypt.compare(password, dbPass);
    } else {
      passOK = password === dbPass;
      if (passOK) {
        const newHash = await bcrypt.hash(password, 10);
        await db.query("UPDATE tbl_users SET password = ?, updated_at = NOW() WHERE id = ?", [
          newHash,
          user.id,
        ]);
      }
    }

    if (!passOK) return res.status(401).json({ error: "Invalid password" });

    const token = jwt.sign(
      { role: "user", id: user.id, fullname: user.fullname, lastname: user.lastname, status: user.status },
      SECRET_KEY,
      { expiresIn: "1h" }
    );

    const { password: _omit, ...safeUser } = user;
    res.json({ message: "Login successful", token, user: safeUser });
  } catch (err) {
    console.error("POST /login error:", err);
    res.status(500).json({ error: "Login failed", code: err.code, sqlMessage: err.sqlMessage });
  }
});

// LOGOUT
app.post(["/logout", "/api/logout"], verifyToken, (req, res) => {
  res.json({ message: "Logged out" });
});

// =========================
//  Swagger
// =========================
app.use("/api-docs", swaggerUi.serve, swaggerUi.setup(specs));

// =========================
//  Start Server
// =========================
async function startServer() {
  try {
    await initializeSchema();
    const PORT = process.env.PORT || 3000;
    app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
  } catch (err) {
    console.error("Server initialization failed:", err);
    process.exit(1);
  }
}

startServer();
