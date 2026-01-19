const express = require("express");
const router = express.Router();
const db = require("../config/db");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const verifyToken = require("../middleware/auth");

const sendError = (res, status, message) =>
  res.status(status).json({ error: message, message });

/**
 * @openapi
 * /api/auth/register:
 *   post:
 *     tags: [Auth]
 *     summary: Register a new user (tbl_users)
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/CreateUserRequest'
 *     responses:
 *       201:
 *         description: Created
 *       400:
 *         description: Bad request
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ErrorResponse'
 *       409:
 *         description: Duplicate username
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
async function handleRegister(req, res) {
  const firstname = String(req.body?.firstname ?? "").trim();
  const fullname = String(req.body?.fullname ?? "").trim();
  const lastname = String(req.body?.lastname ?? "").trim();
  const username = String(req.body?.username ?? "").trim();
  const password = String(req.body?.password ?? "");
  const address = String(req.body?.address ?? "").trim();
  const sex = String(req.body?.sex ?? "").trim();
  const birthday = String(req.body?.birthday ?? "").trim();

  try {
    if (!username) return sendError(res, 400, "Username is required");
    if (!password) return sendError(res, 400, "Password is required");

    const [dupes] = await db.query(
      "SELECT id FROM tbl_users WHERE username = ? LIMIT 1",
      [username]
    );
    if (dupes.length > 0) return sendError(res, 409, "Username already exists");

    const hashedPassword = await bcrypt.hash(password, 10);

    const [result] = await db.query(
      `INSERT INTO tbl_users (firstname, fullname, lastname, username, password, address, sex, birthday)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        firstname || null,
        fullname || null,
        lastname || null,
        username,
        hashedPassword,
        address || null,
        sex || null,
        birthday || null,
      ]
    );

    return res.status(201).json({
      id: result.insertId,
      firstname: firstname || "",
      fullname: fullname || "",
      lastname: lastname || "",
      username,
      address: address || "",
      sex: sex || "",
      birthday: birthday || "",
    });
  } catch (err) {
    console.error("POST /api/auth/register error:", err);
    return sendError(res, 500, "Insert failed");
  }
}

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
 * /api/auth/login:
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
async function handleLogin(req, res) {
  try {
    const username = String(req.body?.username ?? "").trim();
    const password = String(req.body?.password ?? "");

    if (!username || !password) {
      return sendError(res, 400, "username/password is required");
    }

    const [rows] = await db.query(
      `SELECT id, firstname, fullname, lastname, username, password, status
       FROM tbl_users
       WHERE username = ? LIMIT 1`,
      [username]
    );

    if (rows.length === 0) return sendError(res, 401, "User not found");

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

    if (!passOK) return sendError(res, 401, "Invalid password");

    const SECRET_KEY = process.env.SECRET_KEY || process.env.JWT_SECRET;
    if (!SECRET_KEY) return sendError(res, 500, "Server missing SECRET_KEY");

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
    console.error("POST /api/auth/login error:", err);
    sendError(res, 500, "Login failed");
  }
}

router.post("/register", handleRegister);
router.post("/", handleLogin);
router.post("/login", handleLogin);

/**
 * @openapi
 * /api/auth/logout:
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
