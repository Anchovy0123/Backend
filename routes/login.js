const express = require("express");
const router = express.Router();
const db = require("../config/db");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const verifyToken = require("../middleware/auth");

/**
 * @openapi
 * tags:
 *   - name: Auth
 *     description: Login/Logout
 *
 * components:
 *   schemas:
 *     LoginRequest:
 *       type: object
 *       required: [username, password]
 *       properties:
 *         username: { type: string, example: "john" }
 *         password: { type: string, example: "1234" }
 *     LoginResponse:
 *       type: object
 *       properties:
 *         message: { type: string, example: "Login successful" }
 *         token: { type: string, example: "<jwt>" }
 *         user:
 *           type: object
 *           properties:
 *             id: { type: integer, example: 1 }
 *             username: { type: string, example: "john" }
 */

/**
 * @openapi
 * /api/login:
 *   post:
 *     tags: [Auth]
 *     summary: Login (tbl_users) and get JWT
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/LoginRequest'
 *     responses:
 *       200:
 *         description: OK
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/LoginResponse'
 *       400:
 *         description: Missing credentials
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ErrorResponse'
 *       401:
 *         description: Unauthorized
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ErrorResponse'
 *       500:
 *         description: Server error
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ErrorResponse'
 */
router.post("/", async (req, res) => {
  try {
    const username = String(req.body?.username ?? "").trim();
    const password = String(req.body?.password ?? "");

    if (!username || !password) {
      return res.status(400).json({ error: "username/password is required" });
    }

    const [rows] = await db.query(
      `SELECT id, firstname, fullname, lastname, username, password, status
       FROM tbl_users
       WHERE username = ? LIMIT 1`,
      [username]
    );

    if (rows.length === 0) return res.status(401).json({ error: "User not found" });

    const user = rows[0];
    const dbPass = String(user.password ?? "");

    let passOK = false;

    if (dbPass.startsWith("$2")) {
      passOK = await bcrypt.compare(password, dbPass);
    } else {
      // migration from plain-text
      passOK = password === dbPass;
      if (passOK) {
        const newHash = await bcrypt.hash(password, 10);
        await db.query(
          "UPDATE tbl_users SET password = ?, updated_at = NOW() WHERE id = ?",
          [newHash, user.id]
        );
      }
    }

    if (!passOK) return res.status(401).json({ error: "Invalid password" });

    const SECRET_KEY = process.env.SECRET_KEY || process.env.JWT_SECRET;
    if (!SECRET_KEY) return res.status(500).json({ error: "Server missing SECRET_KEY" });

    const token = jwt.sign(
      {
        role: "user",
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
    console.error("POST /api/login error:", err);
    res.status(500).json({ error: "Login failed" });
  }
});

/**
 * @openapi
 * /api/logout:
 *   post:
 *     tags: [Auth]
 *     summary: Logout (JWT stateless) - just a test endpoint
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: OK
 *       401:
 *         description: Unauthorized
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ErrorResponse'
 *       500:
 *         description: Server error
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ErrorResponse'
 */
router.post("/logout", verifyToken, (req, res) => {
  res.json({ message: "Logged out" });
});

module.exports = router;
