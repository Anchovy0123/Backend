// server.js
require("dotenv").config(); // โหลดค่าจาก .env
const verifyToken = require("./middleware/auth"); // ✅ เหลือแค่อันเดียว
const express = require("express");
const mysql = require("mysql2/promise");
const bcrypt = require("bcrypt");
const app = express();
const jwt = require("jsonwebtoken");
const SECRET_KEY = process.env.JWT_SECRET; // ควรเก็บใน .env
const cors = require("cors");
app.use(express.json());

// ใช้ค่าจาก .env
const db = mysql.createPool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT, //เพิ่ม port
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
});

// Route ทดสอบการเชื่อมต่อ
app.get("/ping", async (req, res) => {
  try {
    const [rows] = await db.query("SELECT NOW() AS now");
    res.json({ status: "ok", time: rows[0].now });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Database error" });
  }
});

//POST: เพิ่มผู้ใช้ใหม่ พร้อม hash password
app.post("/users", async (req, res) => {
  const { firstname, fullname, lastname, username, password } = req.body;

  try {
    if (!password)
      return res.status(400).json({ error: "Password is required" });

    // เข้ารหัส password
    const hashedPassword = await bcrypt.hash(password, 10);

    const [result] = await db.query(
      "INSERT INTO tbl_users (firstname, fullname, lastname, username, password) VALUES (?, ?, ?, ?, ?)",
      [firstname, fullname, lastname, username, hashedPassword]
    );

    res.json({ id: result.insertId, firstname, fullname, lastname, username });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Insert failed" });
  }
});

// GET users (protected)
app.get("/users", verifyToken, async (req, res) => {
  try {
    const [rows] = await db.query(
      "SELECT id, firstname, fullname, lastname FROM tbl_users"
    );
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: "Query failed" });
  }
});

// GET user by id (protected)
app.get("/users/:id", verifyToken, async (req, res) => {
  const { id } = req.params;
  try {
    const [rows] = await db.query(
      "SELECT id, firstname, fullname, lastname FROM tbl_users WHERE id = ?",
      [id]
    );
    if (rows.length === 0)
      return res.status(404).json({ message: "User not found" });
    res.json(rows[0]);
  } catch (err) {
    res.status(500).json({ error: "Query failed" });
  }
});
// POST: เข้าสู่ระบบ (Login)
app.post("/login", async (req, res) => {
  try {
    // 1) ป้องกัน body ว่าง/ผิดรูป
    if (!req.body || typeof req.body !== "object") {
      return res.status(400).json({ error: "Invalid request body" });
    }

    const username = String(req.body.username || "").trim();
    const password = String(req.body.password || "").trim();

    if (!username || !password) {
      return res.status(400).json({ error: "username/password is required" });
    }

    // 2) หา user
    const [rows] = await db.query(
      "SELECT * FROM tbl_users WHERE username = ? LIMIT 1",
      [username]
    );
    if (rows.length === 0) {
      return res.status(401).json({ error: "User not found" });
    }
    const user = rows[0];

    // 3) ตรวจรหัสผ่าน
    // ถ้ารหัสใน DB เป็น bcrypt (ขึ้นต้นด้วย $2)
    let passOK = false;
    if (typeof user.password === "string" && user.password.startsWith("$2")) {
      passOK = await bcrypt.compare(password, user.password);
    } else {
      // ยังเป็น plain-text → เทียบตรงๆ
      passOK = password === String(user.password);

      // และถ้าเทียบผ่าน ให้ upgrade เป็น bcrypt โดยอัตโนมัติ (migrate ทันที)
      if (passOK) {
        const newHash = await bcrypt.hash(password, 10);
        await db.query("UPDATE tbl_users SET password = ?, updated_at = NOW() WHERE id = ?", [
          newHash,
          user.id,
        ]);
        user.password = newHash; // sync ในหน่วยความจำ
      }
    }

    if (!passOK) {
      return res.status(401).json({ error: "Invalid password" });
    }

    // 4) สร้าง JWT (อย่าลืมตั้งค่า SECRET_KEY ใน .env)
    const token = jwt.sign(
      { id: user.id, fullname: user.fullname, lastname: user.lastname, status: user.status },
      process.env.SECRET_KEY, // ใช้จาก .env
      { expiresIn: "1h" }
    );

    // 5) ตอบกลับ (อย่าส่ง password กลับ)
    const { password: _omit, ...safeUser } = user;
    res.json({ message: "Login successful", token, user: safeUser });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: "Login failed" });
  }
});

// PUT: อัปเดตข้อมูลผู้ใช้ + เปลี่ยนรหัสผ่านถ้ามีส่งมา
app.put("/users/:id", async (req, res) => {
  const { id } = req.params;
  const { firstname, fullname, lastname, username, password, status } =
    req.body;

  try {
    // Build SET clauses dynamically so optional fields (like password) are handled correctly
    const fields = [];
    const params = [];

    if (firstname !== undefined) {
      fields.push("firstname = ?");
      params.push(firstname);
    }
    if (fullname !== undefined) {
      fields.push("fullname = ?");
      params.push(fullname);
    }
    if (lastname !== undefined) {
      fields.push("lastname = ?");
      params.push(lastname);
    }
    if (username !== undefined) {
      fields.push("username = ?");
      params.push(username);
    }
    if (status !== undefined) {
      fields.push("status = ?");
      params.push(status);
    }

    if (password) {
      const hashedPassword = await bcrypt.hash(password, 10);
      fields.push("password = ?");
      params.push(hashedPassword);
    }

    if (fields.length === 0) {
      return res.status(400).json({ error: "No fields to update" });
    }

    const query = `UPDATE tbl_users SET ${fields.join(", ")} WHERE id = ?`;
    params.push(id);

    const [result] = await db.query(query, params);

    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "User not found" });
    }

    res.json({ message: "User updated successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Update failed" });
  }
});

//DELETE /users/:id - ลบผู้ใช้
app.delete("/users/:id", async (req, res) => {
  const { id } = req.params;
  try {
    const [result] = await db.query("DELETE FROM tbl_users WHERE id = ?", [id]);
    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "User not found" });
    }
    res.json({ message: "User deleted successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Delete failed" });
  }
});

// เริ่มเซิร์ฟเวอร์
app.use(cors());
const PORT = 3000;
app.get("/api/data", (req, res) => {
  res.json({ message: "Hello, CORS!" });
});
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});