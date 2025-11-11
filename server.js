// server.js
require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const verifyToken = require('./middleware/auth');

const app = express();
app.use(express.json());

const db = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
});

const SECRET_KEY = process.env.JWT_SECRET;

// Test DB
app.get('/ping', async (req, res) => {
  try {
    const [rows] = await db.query('SELECT NOW() AS now');
    res.json({ status: 'ok', time: rows[0].now });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Database error' });
  }
});


// ========== AUTH ==========

// POST: สมัครสมาชิก (Public)
app.post('/users', async (req, res) => {
  const { firstname, fullname, lastname, password } = req.body;

  try {
    if (!password) {
      return res.status(400).json({ error: 'Password is required' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const [result] = await db.query(
      'INSERT INTO tbl_users (firstname, fullname, lastname, password) VALUES (?, ?, ?, ?)',
      [firstname, fullname, lastname, hashedPassword]
    );

    res.json({
      id: result.insertId,
      firstname,
      fullname,
      lastname,
      message: 'User created successfully',
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Insert failed' });
  }
});

// POST: Login (Public)
// หมายเหตุ: ที่ frontend ส่ง body เป็น { "username": "...", "password": "..." }
// ถ้าในฐานข้อมูลคุณใช้ "fullname" เป็น username ให้แมปแบบนี้
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res
      .status(400)
      .json({ error: 'username and password are required' });
  }

  try {
    // ถ้า DB มีคอลัมน์ username จริง ให้ใช้ WHERE username = ?
    // ตอนนี้จะใช้ fullname เป็น username ตามตัวอย่าง
    const [rows] = await db.query(
      'SELECT * FROM tbl_users WHERE fullname = ?',
      [username]
    );

    if (rows.length === 0) {
      return res.status(401).json({ error: 'User not found' });
    }

    const user = rows[0];

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid password' });
    }

    // ข้อมูลที่จะฝังใน token
    const payload = {
      id: user.id,
      firstname: user.firstname,
      fullname: user.fullname,
      lastname: user.lastname,
    };

    const token = jwt.sign(payload, SECRET_KEY, { expiresIn: '1h' });

    res.json({
      message: 'Login successful',
      token,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Login failed' });
  }
});


// ========== PROTECTED USER APIs ==========
// ต้องใส่ Authorization: Bearer <token>

// GET users (Protected)
app.get('/users', verifyToken, async (req, res) => {
  try {
    const [rows] = await db.query(
      'SELECT id, firstname, fullname, lastname FROM tbl_users'
    );
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Query failed' });
  }
});

// GET user by id (Protected)
app.get('/users/:id', verifyToken, async (req, res) => {
  const { id } = req.params;
  try {
    const [rows] = await db.query(
      'SELECT id, firstname, fullname, lastname FROM tbl_users WHERE id = ?',
      [id]
    );
    if (rows.length === 0)
      return res.status(404).json({ message: 'User not found' });
    res.json(rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Query failed' });
  }
});

// PUT: อัปเดตข้อมูลผู้ใช้ (Protected)
app.put('/users/:id', verifyToken, async (req, res) => {
  const { id } = req.params;
  const { firstname, fullname, lastname, password } = req.body;

  try {
    let query =
      'UPDATE tbl_users SET firstname = ?, fullname = ?, lastname = ?';
    const params = [firstname, fullname, lastname];

    if (password) {
      const hashedPassword = await bcrypt.hash(password, 10);
      query += ', password = ?';
      params.push(hashedPassword);
    }

    query += ' WHERE id = ?';
    params.push(id);

    const [result] = await db.query(query, params);

    if (result.affectedRows === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.json({ message: 'User updated successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Update failed' });
  }
});

// DELETE user (Protected)
app.delete('/users/:id', verifyToken, async (req, res) => {
  const { id } = req.params;
  try {
    const [result] = await db.query('DELETE FROM tbl_users WHERE id = ?', [
      id,
    ]);
    if (result.affectedRows === 0)
      return res.status(404).json({ message: 'User not found' });
    res.json({ message: 'User deleted successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Delete failed' });
  }
});


const PORT = process.env.PORT || 3000;
app.listen(PORT, () =>
  console.log(`Server running on http://localhost:${PORT}`)
);
