const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const db = require("../../config/db");
const { authMiddleware, COOKIE_NAME } = require("../authMiddleware");

const router = express.Router();

const TOKEN_TTL_MS = 7 * 24 * 60 * 60 * 1000;

const getCookieOptions = () => ({
  httpOnly: true,
  secure: process.env.NODE_ENV === "production",
  sameSite: "none",
  maxAge: TOKEN_TTL_MS,
  path: "/",
});

const sendError = (res, status, message) => {
  res.status(status).json({ error: message });
};

router.post("/register", async (req, res) => {
  try {
    const email = String(req.body?.email ?? "").trim().toLowerCase();
    const password = String(req.body?.password ?? "");

    if (!email || !password) {
      return sendError(res, 400, "email and password are required");
    }

    const [existing] = await db.query(
      "SELECT id FROM tbl_users WHERE username = ? LIMIT 1",
      [email]
    );
    if (existing.length > 0) {
      return sendError(res, 400, "Email already exists");
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const [result] = await db.query(
      "INSERT INTO tbl_users (username, password) VALUES (?, ?)",
      [email, hashedPassword]
    );

    return res.status(201).json({
      ok: true,
      user: { id: result.insertId, email },
    });
  } catch (err) {
    console.error("POST /api/auth/register error:", err);
    return sendError(res, 500, "Register failed");
  }
});

router.post("/login", async (req, res) => {
  try {
    const email = String(req.body?.email ?? "").trim().toLowerCase();
    const password = String(req.body?.password ?? "");

    if (!email || !password) {
      return sendError(res, 400, "email and password are required");
    }

    const [rows] = await db.query(
      "SELECT id, username, password FROM tbl_users WHERE username = ? LIMIT 1",
      [email]
    );
    if (rows.length === 0) {
      return sendError(res, 401, "Invalid credentials");
    }

    const user = rows[0];
    const passwordOk = await bcrypt.compare(password, String(user.password ?? ""));
    if (!passwordOk) {
      return sendError(res, 401, "Invalid credentials");
    }

    const secret = process.env.JWT_SECRET;
    if (!secret) {
      return sendError(res, 500, "Server misconfigured");
    }

    const token = jwt.sign(
      { id: user.id, email: user.username },
      secret,
      { expiresIn: "7d" }
    );

    res.cookie(COOKIE_NAME, token, getCookieOptions());
    return res.json({ ok: true, user: { id: user.id, email: user.username } });
  } catch (err) {
    console.error("POST /api/auth/login error:", err);
    return sendError(res, 500, "Login failed");
  }
});

router.post("/logout", authMiddleware, (req, res) => {
  res.clearCookie(COOKIE_NAME, getCookieOptions());
  res.json({ ok: true });
});

router.get("/me", authMiddleware, async (req, res) => {
  try {
    const [rows] = await db.query(
      "SELECT id, username FROM tbl_users WHERE id = ? LIMIT 1",
      [req.user.id]
    );
    if (rows.length === 0) {
      return sendError(res, 401, "Unauthorized");
    }

    const user = rows[0];
    return res.json({ ok: true, user: { id: user.id, email: user.username } });
  } catch (err) {
    console.error("GET /api/auth/me error:", err);
    return sendError(res, 500, "Failed to load user");
  }
});

module.exports = router;
