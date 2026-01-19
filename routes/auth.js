const express = require("express");
const router = express.Router();
const bcrypt = require("bcryptjs");
const db = require("../config/db");

const requiredFields = [
  "firstname",
  "fullname",
  "lastname",
  "username",
  "address",
  "sex",
  "birthday",
  "password",
];

router.post("/register", async (req, res) => {
  const body = req.body ?? {};
  const missing = requiredFields.filter((field) => {
    const value = body[field];
    return value === undefined || value === null || String(value).trim() === "";
  });

  if (missing.length > 0) {
    return res.status(400).json({
      error: "Missing required fields",
      missing,
    });
  }

  const firstname = String(body.firstname).trim();
  const fullname = String(body.fullname).trim();
  const lastname = String(body.lastname).trim();
  const username = String(body.username).trim();
  const address = String(body.address).trim();
  const sex = String(body.sex).trim();
  const birthday = String(body.birthday).trim();
  const password = String(body.password);

  try {
    const [dupes] = await db.query(
      "SELECT id FROM tbl_users WHERE username = ? LIMIT 1",
      [username]
    );
    if (dupes.length > 0) {
      return res.status(409).json({ error: "Username already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    await db.query(
      `INSERT INTO tbl_users (firstname, fullname, lastname, username, password, address, sex, birthday)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [firstname, fullname, lastname, username, hashedPassword, address, sex, birthday]
    );

    return res.status(201).json({ message: "register success" });
  } catch (err) {
    console.error("POST /api/auth/register error:", err);
    return res.status(500).json({ error: "Register failed" });
  }
});

module.exports = router;
