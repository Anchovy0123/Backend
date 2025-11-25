// server.js
require("dotenv").config(); // โหลดค่าจาก .env

const express = require("express");
const mysql = require("mysql2/promise");
const bcrypt = require("bcryptjs"); // ใช้ bcryptjs ตามโจทย์
const jwt = require("jsonwebtoken");
const cors = require("cors");
const verifyToken = require("./middleware/auth"); // ใช้กับ route /users เดิม

const app = express();

// ✅ กำหนด SECRET_KEY ให้ชัดเจน
// ถ้าไม่มี SECRET_KEY ให้ fallback ไปใช้ JWT_SECRET
const SECRET_KEY = process.env.SECRET_KEY || process.env.JWT_SECRET;

app.use(cors());
app.use(express.json());

// =========================
//  เชื่อมต่อฐานข้อมูล
// =========================
const db = mysql.createPool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
});

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

  try {
    await db.query(createUsersTableSQL);
    console.log("tbl_users table is ready");
  } catch (err) {
    console.error("Failed to ensure tbl_users table:", err);
    throw err;
  }
}



// ทดสอบการเชื่อมต่อ
app.get("/ping", async (req, res) => {
  try {
    const [rows] = await db.query("SELECT NOW() AS now");
    res.json({ status: "ok", time: rows[0].now });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Database error" });
  }
});

// =========================
//  ส่วนของ tbl_users (เดิม)
// =========================

// POST: เพิ่มผู้ใช้ใหม่ พร้อม hash password
app.post("/users", async (req, res) => {
  const { firstname, fullname, lastname, username, password } = req.body;

  try {
    // กัน username ซ้ำ
    if (username) {
      const [dupes] = await db.query(
        "SELECT id FROM tbl_users WHERE username = ? LIMIT 1",
        [username]
      );
      if (dupes.length > 0) {
        return res.status(409).json({ error: "Username already exists" });
      }
    }

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
    console.error("GET /users error:", err);
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

// POST: Login สำหรับ tbl_users (เดิม)
app.post("/login", async (req, res) => {
  try {
    if (!req.body || typeof req.body !== "object") {
      return res.status(400).json({ error: "Invalid request body" });
    }

    const username = String(req.body.username || "").trim();
    const password = String(req.body.password || "").trim();

    if (!username || !password) {
      return res.status(400).json({ error: "username/password is required" });
    }

    // หา user ตาม username
    const [rows] = await db.query(
      "SELECT * FROM tbl_users WHERE username = ? ORDER BY id DESC",
      [username]
    );
    if (rows.length === 0) {
      return res.status(401).json({ error: "User not found" });
    }
    let user = rows[0];

    // ตรวจรหัสผ่าน (รองรับทั้ง plain-text และ bcrypt)
    let passOK = false;
    if (typeof user.password === "string" && user.password.startsWith("$2")) {
      passOK = await bcrypt.compare(password, user.password);
    } else {
      passOK = password === String(user.password);
      if (passOK) {
        const newHash = await bcrypt.hash(password, 10);
        await db.query(
          "UPDATE tbl_users SET password = ?, updated_at = NOW() WHERE id = ?",
          [newHash, user.id]
        );
        user.password = newHash;
      }
    }

    if (!passOK) {
      for (let i = 1; i < rows.length && !passOK; i++) {
        const candidate = rows[i];
        if (
          typeof candidate.password === "string" &&
          candidate.password.startsWith("$2")
        ) {
          passOK = await bcrypt.compare(password, candidate.password);
        } else {
          passOK = password === String(candidate.password);
          if (passOK) {
            const newHash = await bcrypt.hash(password, 10);
            await db.query(
              "UPDATE tbl_users SET password = ?, updated_at = NOW() WHERE id = ?",
              [newHash, candidate.id]
            );
            candidate.password = newHash;
          }
        }
        if (passOK) {
          user = candidate;
          break;
        }
      }

      if (!passOK) {
        return res.status(401).json({ error: "Invalid password" });
      }
    }

    // สร้าง JWT สำหรับฝั่ง users
    const token = jwt.sign(
      {
        id: user.id,
        fullname: user.fullname,
        lastname: user.lastname,
        status: user.status,
      },
      SECRET_KEY,
      { expiresIn: "1h" }
    );

    const { password: _omit, ...safeUser } = user;
    res.json({ message: "Login successful", token, user: safeUser });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: "Login failed" });
  }
});

// PUT: อัปเดตข้อมูลผู้ใช้
app.put("/users/:id", async (req, res) => {
  const { id } = req.params;
  const { firstname, fullname, lastname, username, password, status } =
    req.body;

  try {
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

// DELETE: ลบผู้ใช้
app.delete("/users/:id", async (req, res) => {
  const { id } = req.params;
  try {
    const [result] = await db.query("DELETE FROM tbl_users WHERE id = ?", [
      id,
    ]);
    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "User not found" });
    }
    res.json({ message: "User deleted successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Delete failed" });
  }
});

// POST: Logout (สำหรับ JWT ฝั่ง users)
app.post("/logout", verifyToken, (req, res) => {
  res.json({ message: "Logged out" });
});

// =========================
//  ส่วนของ tbl_customers
//  (Register + Login ตามโจทย์)
// =========================

// GET: รายชื่อลูกค้า (protected)
app.get("/customers", verifyToken, async (req, res) => {
  try {
    const [rows] = await db.query(
      `SELECT customer_id, username, full_name, address, phone, email, created_at
       FROM tbl_customers`
    );
    res.json(rows);
  } catch (err) {
    console.error("GET /customers error:", err);
    res.status(500).json({ error: "Query failed" });
  }
});

// Register: POST /auth/register
app.post("/auth/register", async (req, res) => {
  try {
    const { username, password, full_name, address, phone, email } = req.body;

    if (!username || !password || !full_name) {
      return res.status(400).json({
        error: "กรุณาส่ง username, password, full_name มาด้วย",
      });
    }

    // เช็ก username ซ้ำใน tbl_customers
    const [dupes] = await db.query(
      "SELECT customer_id FROM tbl_customers WHERE username = ? LIMIT 1",
      [username]
    );

    if (dupes.length > 0) {
      return res.status(409).json({
        error: "username นี้ถูกใช้แล้ว",
      });
    }

    // hash password ด้วย bcryptjs
    const hashedPassword = await bcrypt.hash(password, 10);

    const [result] = await db.query(
      `INSERT INTO tbl_customers 
       (username, password, full_name, address, phone, email)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [username, hashedPassword, full_name, address || null, phone || null, email || null]
    );

    res.status(201).json({
      message: "ลงทะเบียนสำเร็จ",
      customer_id: result.insertId,
      username,
      full_name,
    });
  } catch (err) {
    console.error("POST /auth/register error:", err);
    res.status(500).json({
      error: "เกิดข้อผิดพลาดในเซิร์ฟเวอร์",
    });
  }
});

// Login: POST /auth/login
app.post("/auth/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    // เช็กว่ากรอกครบไหม
    if (!username || !password) {
      return res.status(400).json({
        error: "กรุณาส่ง username และ password",
      });
    }

    // หา user จาก tbl_customers
    const [rows] = await db.query(
      "SELECT * FROM tbl_customers WHERE username = ? LIMIT 1",
      [username]
    );

    if (rows.length === 0) {
      return res.status(401).json({
        error: "ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง",
      });
    }

    const user = rows[0];

    // เทียบ password กับ hash
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({
        error: "ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง",
      });
    }

    // สร้าง JWT อายุ 1 ชั่วโมง
    const payload = {
      customer_id: user.customer_id,
      username: user.username,
    };

    const token = jwt.sign(payload, SECRET_KEY, { expiresIn: "1h" });

    res.json({ token });
  } catch (err) {
    console.error("POST /auth/login error:", err);
    res.status(500).json({
      error: "เกิดข้อผิดพลาดในเซิร์ฟเวอร์",
    });
  }
});

// =========================
//  เมนูอาหาร + ร้านอาหาร
// =========================
app.get("/menus", async (req, res) => {
  try {
    const [rows] = await db.query(
      `SELECT 
         m.menu_id,
         m.menu_name,
         m.description,
         m.price,
         m.category,
         m.is_active,
         r.restaurant_id,
         r.restaurant_name,
         r.address AS restaurant_address,
         r.phone AS restaurant_phone,
         r.menu_detail AS restaurant_menu_detail
       FROM tbl_menus AS m
       INNER JOIN tbl_restaurants AS r ON m.restaurant_id = r.restaurant_id
       ORDER BY r.restaurant_name, m.menu_name`
    );
    res.json(rows);
  } catch (err) {
    console.error("GET /menus error:", err);
    res.status(500).json({ error: "Query failed" });
  }
});

// =========================
//  Orders
// =========================
app.post("/orders", verifyToken, async (req, res) => {
  const customerId = req.user && req.user.customer_id;
  const { menu_id, quantity } = req.body || {};

  if (!customerId) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  if (menu_id === undefined || quantity === undefined) {
    return res
      .status(400)
      .json({ error: "menu_id and quantity are required" });
  }

  try {
    const [menuRows] = await db.query(
      "SELECT menu_id, price, restaurant_id FROM tbl_menus WHERE menu_id = ? LIMIT 1",
      [menu_id]
    );

    if (menuRows.length === 0) {
      return res.status(404).json({ error: "Menu not found" });
    }

    const menu = menuRows[0];
    const priceEach = Number(menu.price);
    const qty = Number(quantity);

    if (!Number.isFinite(priceEach) || !Number.isFinite(qty) || qty <= 0) {
      return res
        .status(400)
        .json({ error: "Invalid menu price or quantity value" });
    }

    const totalPrice = priceEach * qty;

    const conn = await db.getConnection();
    try {
      await conn.beginTransaction();

      const [orderResult] = await conn.query(
        "INSERT INTO tbl_orders (customer_id, restaurant_id, total_amount) VALUES (?, ?, ?)",
        [customerId, menu.restaurant_id, totalPrice]
      );

      const orderId = orderResult.insertId;

      await conn.query(
        `INSERT INTO tbl_order_items 
           (order_id, menu_id, quantity, price_each, subtotal)
         VALUES (?, ?, ?, ?, ?)`,
        [orderId, menu.menu_id, qty, priceEach, totalPrice]
      );

      await conn.commit();

      res.status(201).json({
        order_id: orderId,
        customer_id: customerId,
        restaurant_id: menu.restaurant_id,
        total_price: totalPrice,
      });
    } catch (err) {
      await conn.rollback();
      throw err;
    } finally {
      conn.release();
    }
  } catch (err) {
    console.error("POST /orders error:", err);
    res.status(500).json({ error: "Order creation failed" });
  }
});

app.get("/orders/summary", verifyToken, async (req, res) => {
  const customerId = req.user && req.user.customer_id;
  if (!customerId) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  try {
    const [rows] = await db.query(
      `SELECT 
         c.full_name AS customer_name,
         COALESCE(SUM(oi.quantity * m.price), 0) AS total_amount
       FROM tbl_customers AS c
       LEFT JOIN tbl_orders AS o ON c.customer_id = o.customer_id
       LEFT JOIN tbl_order_items AS oi ON o.order_id = oi.order_id
       LEFT JOIN tbl_menus AS m ON oi.menu_id = m.menu_id
       WHERE c.customer_id = ?
       GROUP BY c.customer_id, c.full_name`,
      [customerId]
    );

    if (rows.length === 0) {
      return res.status(404).json({ error: "Customer not found" });
    }

    const summary = rows[0];
    res.json({
      customer_name: summary.customer_name || "",
      total_amount: Number(summary.total_amount) || 0,
    });
  } catch (err) {
    console.error("GET /orders/summary error:", err);
    res.status(500).json({ error: "Summary query failed" });
  }
});

// =========================
//  ทดสอบ CORS
// =========================
app.get("/api/data", (req, res) => {
  res.json({ message: "Hello, CORS!" });
});

// เริ่มเซิร์ฟเวอร์
async function startServer() {
  try {
    await initializeSchema();
    const PORT = process.env.PORT || 3000;
    app.listen(PORT, () => {
      console.log(`Server is running on port ${PORT}`);
    });
  } catch (err) {
    console.error("Server initialization failed:", err);
    process.exit(1);
  }
}

startServer();

