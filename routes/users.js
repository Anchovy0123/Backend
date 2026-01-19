const express = require("express");
const router = express.Router();
const db = require("../config/db");
const bcrypt = require("bcryptjs");

const sendError = (res, status, message) =>
  res.status(status).json({ error: message, message });

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
 *         address: { type: string, example: "123 Main St" }
 *         sex: { type: string, example: "male" }
 *         birthday: { type: string, example: "2002-02-14" }
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
 *         address: { type: string }
 *         sex: { type: string }
 *         birthday: { type: string, example: "2002-02-14" }
 *     UpdateUserRequest:
 *       type: object
 *       properties:
 *         id: { type: integer, example: 1 }
 *         firstname: { type: string }
 *         fullname: { type: string }
 *         lastname: { type: string }
 *         username: { type: string }
 *         password: { type: string }
 *         address: { type: string }
 *         sex: { type: string }
 *         birthday: { type: string, example: "2002-02-14" }
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
    console.error("POST /api/users error:", err);
    const baseMessage = "Insert failed";
    if (process.env.NODE_ENV === "production") {
      return sendError(res, 500, baseMessage);
    }
    const detail = err?.sqlMessage || err?.message || "";
    const code = err?.code ? ` (${err.code})` : "";
    return sendError(res, 500, detail ? `${baseMessage}${code}: ${detail}` : `${baseMessage}${code}`);
  }
});

/**
 * @openapi
 * /api/users:
 *   get:
 *     tags: [Users]
 *     summary: List all users
 *     responses:
 *       200:
 *         description: OK
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 $ref: '#/components/schemas/User'
 *       500:
 *         description: Server error
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ErrorResponse'
 */
router.get("/", async (req, res) => {
  try {
    const [rows] = await db.query(
      `SELECT id, firstname, fullname, lastname, username, address, sex, birthday, status, created_at
       FROM tbl_users
       ORDER BY id DESC`
    );
    res.json(rows);
  } catch (err) {
    console.error("GET /api/users error:", err);
    sendError(res, 500, "Query failed");
  }
});

/**
 * @openapi
 * /api/users:
 *   put:
 *     tags: [Users]
 *     summary: Update user by id (body.id)
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

/**
 * @openapi
 * /api/users/{id}:
 *   get:
 *     tags: [Users]
 *     summary: Get user by id
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
router.get("/:id", async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) return sendError(res, 400, "Invalid id");

  try {
    const [rows] = await db.query(
      `SELECT id, firstname, fullname, lastname, username, address, sex, birthday, status, created_at
       FROM tbl_users
       WHERE id = ? LIMIT 1`,
      [id]
    );
    if (rows.length === 0) return sendError(res, 404, "User not found");
    res.json(rows[0]);
  } catch (err) {
    console.error("GET /api/users/:id error:", err);
    sendError(res, 500, "Query failed");
  }
});

/**
 * @openapi
 * /api/users/{id}:
 *   put:
 *     tags: [Users]
 *     summary: Update user by id
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
async function updateUser(req, res, rawId) {
  const id = Number(rawId);
  if (!Number.isInteger(id) || id <= 0) return sendError(res, 400, "Invalid id");

  const firstname = req.body.firstname !== undefined ? String(req.body.firstname).trim() : undefined;
  const fullname = req.body.fullname !== undefined ? String(req.body.fullname).trim() : undefined;
  const lastname = req.body.lastname !== undefined ? String(req.body.lastname).trim() : undefined;
  const username = req.body.username !== undefined ? String(req.body.username).trim() : undefined;
  const status = req.body.status !== undefined ? String(req.body.status) : undefined;
  const password = req.body.password !== undefined ? String(req.body.password) : undefined;
  const address = req.body.address !== undefined ? String(req.body.address).trim() : undefined;
  const sex = req.body.sex !== undefined ? String(req.body.sex).trim() : undefined;
  const birthday = req.body.birthday !== undefined ? String(req.body.birthday).trim() : undefined;

  try {
    const fields = [];
    const params = [];

    if (username !== undefined) {
      if (!username) return sendError(res, 400, "Username cannot be empty");

      const [dupes] = await db.query(
        "SELECT id FROM tbl_users WHERE username = ? AND id <> ? LIMIT 1",
        [username, id]
      );
      if (dupes.length > 0) return sendError(res, 409, "Username already exists");

      fields.push("username = ?");
      params.push(username);
    }

    if (firstname !== undefined) {
      fields.push("firstname = ?");
      params.push(firstname || null);
    }
    if (fullname !== undefined) {
      fields.push("fullname = ?");
      params.push(fullname || null);
    }
    if (lastname !== undefined) {
      fields.push("lastname = ?");
      params.push(lastname || null);
    }
    if (address !== undefined) {
      fields.push("address = ?");
      params.push(address || null);
    }
    if (sex !== undefined) {
      fields.push("sex = ?");
      params.push(sex || null);
    }
    if (birthday !== undefined) {
      fields.push("birthday = ?");
      params.push(birthday || null);
    }
    if (status !== undefined) {
      fields.push("status = ?");
      params.push(status);
    }

    if (password !== undefined) {
      if (!password) return sendError(res, 400, "Password cannot be empty");
      const hashedPassword = await bcrypt.hash(password, 10);
      fields.push("password = ?");
      params.push(hashedPassword);
    }

    if (fields.length === 0) return sendError(res, 400, "No fields to update");

    const sql = `UPDATE tbl_users SET ${fields.join(", ")}, updated_at = NOW() WHERE id = ?`;
    params.push(id);

    const [result] = await db.query(sql, params);
    if (result.affectedRows === 0) return sendError(res, 404, "User not found");

    res.json({ message: "User updated successfully" });
  } catch (err) {
    console.error("PUT /api/users error:", err);
    sendError(res, 500, "Update failed");
  }
}

router.put("/", async (req, res) => updateUser(req, res, req.body?.id));
router.put("/:id", async (req, res) => updateUser(req, res, req.params.id));

/**
 * @openapi
 * /api/users/{id}:
 *   delete:
 *     tags: [Users]
 *     summary: Delete user by id
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
router.delete("/:id", async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) return sendError(res, 400, "Invalid id");

  try {
    const [result] = await db.query("DELETE FROM tbl_users WHERE id = ?", [id]);
    if (result.affectedRows === 0) return sendError(res, 404, "User not found");
    res.json({ message: "User deleted successfully" });
  } catch (err) {
    console.error("DELETE /api/users/:id error:", err);
    sendError(res, 500, "Delete failed");
  }
});

module.exports = router;
