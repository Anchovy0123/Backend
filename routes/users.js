const express = require("express");
const router = express.Router();
const db = require("../config/db");
const bcrypt = require("bcryptjs");
const verifyToken = require("../middleware/auth");

/**
 * @openapi
 * tags:
 *   - name: Users
 *     description: Manage tbl_users
 *
 * components:
 *   schemas:
 *     User:
 *       type: object
 *       properties:
 *         id: { type: integer, example: 1 }
 *         firstname: { type: string, example: "John" }
 *         fullname: { type: string, example: "John A." }
 *         lastname: { type: string, example: "Doe" }
 *         username: { type: string, example: "john" }
 *         status: { type: string, example: "active" }
 *         created_at: { type: string, example: "2026-01-05T10:00:00.000Z" }
 *     CreateUserRequest:
 *       type: object
 *       required: [username, password]
 *       properties:
 *         firstname: { type: string }
 *         fullname: { type: string }
 *         lastname: { type: string }
 *         username: { type: string, example: "john" }
 *         password: { type: string, example: "1234" }
 *     UpdateUserRequest:
 *       type: object
 *       properties:
 *         firstname: { type: string }
 *         fullname: { type: string }
 *         lastname: { type: string }
 *         username: { type: string }
 *         password: { type: string }
 *         status: { type: string }
 *     ErrorResponse:
 *       type: object
 *       required: [error]
 *       properties:
 *         error: { type: string, example: "Username is required" }
 */

/**
 * @openapi
 * /api/users:
 *   post:
 *     tags: [Users]
 *     summary: Create a new user
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
router.post("/", async (req, res) => {
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
    console.error("POST /api/users error:", err);
    return res.status(500).json({ error: "Insert failed" });
  }
});

/**
 * @openapi
 * /api/users:
 *   get:
 *     tags: [Users]
 *     summary: List all users (protected)
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: OK
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 $ref: '#/components/schemas/User'
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
router.get("/", verifyToken, async (req, res) => {
  try {
    const [rows] = await db.query(
      `SELECT id, firstname, fullname, lastname, username, status, created_at
       FROM tbl_users
       ORDER BY id DESC`
    );
    res.json(rows);
  } catch (err) {
    console.error("GET /api/users error:", err);
    res.status(500).json({ error: "Query failed" });
  }
});

/**
 * @openapi
 * /api/users/{id}:
 *   get:
 *     tags: [Users]
 *     summary: Get user by id (protected)
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema: { type: integer, example: 1 }
 *     responses:
 *       200:
 *         description: OK
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/User'
 *       400:
 *         description: Invalid id
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
 *       404:
 *         description: Not found
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
router.get("/:id", verifyToken, async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: "Invalid id" });

  try {
    const [rows] = await db.query(
      `SELECT id, firstname, fullname, lastname, username, status, created_at
       FROM tbl_users
       WHERE id = ? LIMIT 1`,
      [id]
    );
    if (rows.length === 0) return res.status(404).json({ error: "User not found" });
    res.json(rows[0]);
  } catch (err) {
    console.error("GET /api/users/:id error:", err);
    res.status(500).json({ error: "Query failed" });
  }
});

/**
 * @openapi
 * /api/users/{id}:
 *   put:
 *     tags: [Users]
 *     summary: Update user by id (protected)
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema: { type: integer, example: 1 }
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/UpdateUserRequest'
 *     responses:
 *       200:
 *         description: OK
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message: { type: string, example: "User updated successfully" }
 *       400:
 *         description: Invalid input
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
 *       404:
 *         description: Not found
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
router.put("/:id", verifyToken, async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: "Invalid id" });

  const firstname = req.body.firstname !== undefined ? String(req.body.firstname).trim() : undefined;
  const fullname  = req.body.fullname  !== undefined ? String(req.body.fullname).trim()  : undefined;
  const lastname  = req.body.lastname  !== undefined ? String(req.body.lastname).trim()  : undefined;
  const username  = req.body.username  !== undefined ? String(req.body.username).trim()  : undefined;
  const status    = req.body.status    !== undefined ? String(req.body.status) : undefined;
  const password  = req.body.password  !== undefined ? String(req.body.password) : undefined;

  try {
    const fields = [];
    const params = [];

    if (username !== undefined) {
      if (!username) return res.status(400).json({ error: "Username cannot be empty" });

      const [dupes] = await db.query(
        "SELECT id FROM tbl_users WHERE username = ? AND id <> ? LIMIT 1",
        [username, id]
      );
      if (dupes.length > 0) return res.status(409).json({ error: "Username already exists" });

      fields.push("username = ?");
      params.push(username);
    }

    if (firstname !== undefined) { fields.push("firstname = ?"); params.push(firstname || null); }
    if (fullname  !== undefined) { fields.push("fullname = ?");  params.push(fullname  || null); }
    if (lastname  !== undefined) { fields.push("lastname = ?");  params.push(lastname  || null); }
    if (status    !== undefined) { fields.push("status = ?");    params.push(status); }

    if (password !== undefined) {
      if (!password) return res.status(400).json({ error: "Password cannot be empty" });
      const hashedPassword = await bcrypt.hash(password, 10);
      fields.push("password = ?");
      params.push(hashedPassword);
    }

    if (fields.length === 0) return res.status(400).json({ error: "No fields to update" });

    const sql = `UPDATE tbl_users SET ${fields.join(", ")}, updated_at = NOW() WHERE id = ?`;
    params.push(id);

    const [result] = await db.query(sql, params);
    if (result.affectedRows === 0) return res.status(404).json({ error: "User not found" });

    res.json({ message: "User updated successfully" });
  } catch (err) {
    console.error("PUT /api/users/:id error:", err);
    res.status(500).json({ error: "Update failed" });
  }
});

/**
 * @openapi
 * /api/users/{id}:
 *   delete:
 *     tags: [Users]
 *     summary: Delete user by id (protected)
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema: { type: integer, example: 1 }
 *     responses:
 *       200:
 *         description: OK
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message: { type: string, example: "User deleted successfully" }
 *       400:
 *         description: Invalid id
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
 *       404:
 *         description: Not found
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
router.delete("/:id", verifyToken, async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: "Invalid id" });

  try {
    const [result] = await db.query("DELETE FROM tbl_users WHERE id = ?", [id]);
    if (result.affectedRows === 0) return res.status(404).json({ error: "User not found" });
    res.json({ message: "User deleted successfully" });
  } catch (err) {
    console.error("DELETE /api/users/:id error:", err);
    res.status(500).json({ error: "Delete failed" });
  }
});

module.exports = router;
