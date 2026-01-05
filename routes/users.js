// =========================
//  USERS (tbl_users)
// =========================

// CREATE user
app.post("/users", async (req, res) => {
  const firstname = String(req.body?.firstname ?? "").trim();
  const fullname  = String(req.body?.fullname ?? "").trim();
  const lastname  = String(req.body?.lastname ?? "").trim();
  const username  = String(req.body?.username ?? "").trim();
  const password  = String(req.body?.password ?? "");

  try {
    if (!username) return res.status(400).json({ error: "Username is required" });
    if (!password) return res.status(400).json({ error: "Password is required" });

    // กัน username ซ้ำ
    const [dupes] = await db.query(
      "SELECT id FROM tbl_users WHERE username = ? LIMIT 1",
      [username]
    );
    if (dupes.length > 0) {
      return res.status(409).json({ error: "Username already exists" });
    }

    // bcrypt hash (แนะนำให้ tbl_users.password เป็น VARCHAR(255))
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
      hint:
        err.code === "ER_DATA_TOO_LONG"
          ? "ตาราง tbl_users ช่อง password สั้นไป → แก้เป็น VARCHAR(255)"
          : undefined,
    });
  }
});

// GET users (protected)
app.get("/users", verifyToken, async (req, res) => {
  try {
    const [rows] = await db.query(
      `SELECT id, firstname, fullname, lastname, username, status, created_at
       FROM tbl_users
       ORDER BY id DESC`
    );
    res.json(rows);
  } catch (err) {
    console.error("GET /users error:", err);
    res.status(500).json({ error: "Query failed", code: err.code, sqlMessage: err.sqlMessage });
  }
});

// GET user by id (protected)
app.get("/users/:id", verifyToken, async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) {
    return res.status(400).json({ error: "Invalid id" });
  }

  try {
    const [rows] = await db.query(
      `SELECT id, firstname, fullname, lastname, username, status, created_at
       FROM tbl_users
       WHERE id = ? LIMIT 1`,
      [id]
    );

    if (rows.length === 0) return res.status(404).json({ message: "User not found" });
    res.json(rows[0]);
  } catch (err) {
    console.error("GET /users/:id error:", err);
    res.status(500).json({ error: "Query failed", code: err.code, sqlMessage: err.sqlMessage });
  }
});

// LOGIN users (simplify + safer)
app.post("/login", async (req, res) => {
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

    // รองรับทั้ง plain-text และ bcrypt (migration)
    let passOK = false;
    if (dbPass.startsWith("$2")) {
      passOK = await bcrypt.compare(password, dbPass);
    } else {
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
    console.error("Login error:", err);
    res.status(500).json({ error: "Login failed", code: err.code, sqlMessage: err.sqlMessage });
  }
});

// UPDATE user (protected + check username dupes)
app.put("/users/:id", verifyToken, async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) {
    return res.status(400).json({ error: "Invalid id" });
  }

  const firstname = req.body.firstname !== undefined ? String(req.body.firstname).trim() : undefined;
  const fullname  = req.body.fullname  !== undefined ? String(req.body.fullname).trim()  : undefined;
  const lastname  = req.body.lastname  !== undefined ? String(req.body.lastname).trim()  : undefined;
  const username  = req.body.username  !== undefined ? String(req.body.username).trim()  : undefined;
  const status    = req.body.status    !== undefined ? req.body.status : undefined;
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
    if (result.affectedRows === 0) return res.status(404).json({ message: "User not found" });

    res.json({ message: "User updated successfully" });
  } catch (err) {
    console.error("PUT /users/:id error:", err);
    res.status(500).json({ error: "Update failed", code: err.code, sqlMessage: err.sqlMessage });
  }
});

// DELETE user (protected)
app.delete("/users/:id", verifyToken, async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) {
    return res.status(400).json({ error: "Invalid id" });
  }

  try {
    const [result] = await db.query("DELETE FROM tbl_users WHERE id = ?", [id]);
    if (result.affectedRows === 0) return res.status(404).json({ message: "User not found" });
    res.json({ message: "User deleted successfully" });
  } catch (err) {
    console.error("DELETE /users/:id error:", err);
    res.status(500).json({ error: "Delete failed", code: err.code, sqlMessage: err.sqlMessage });
  }
});

// LOGOUT (JWT stateless)
app.post("/logout", verifyToken, (req, res) => {
  res.json({ message: "Logged out" });
});
