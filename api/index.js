// api/index.js
require("dotenv").config({
  path:
    process.env.DOTENV_CONFIG_PATH ||
    (process.env.NODE_ENV === "production" ? ".env.production" : ".env.local"),
  override: true,
});

const express = require("express");
const cors = require("cors");

const db = require("../config/db");
const { swaggerUi, specs } = require("../swagger");

const app = express();
app.use(cors());
app.use(express.json());

// ---- Health ----
app.get("/ping", async (req, res) => {
  try {
    const [rows] = await db.query("SELECT NOW() AS now");
    return res.json({ status: "ok", time: rows[0].now });
  } catch (err) {
    console.error("GET /ping error:", err);
    return res.status(500).json({ error: "Database error" });
  }
});

// ---- Routes ----
app.use("/api/users", require("../routes/users"));
app.use("/api/login", require("../routes/login"));

// ---- Swagger ----
app.get("/api-docs.json", (req, res) => res.json(specs));

app.use(
  "/api-docs",
  swaggerUi.serve,
  swaggerUi.setup(specs, {
    explorer: true,
    swaggerOptions: { persistAuthorization: true },
  })
);

// (optional) init schema แบบไม่บล็อก swagger
async function initializeSchema() {
  const sql = `
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
  await db.query(sql);
}

async function startLocal() {
  try {
    try {
      await initializeSchema();
      console.log("DB connected & schema ready");
    } catch (e) {
      console.warn("⚠️ DB init failed (server will still start):", e.message);
    }

    const PORT = process.env.PORT || 3000;
    app.listen(PORT, () => {
      console.log(`Server running on http://localhost:${PORT}`);
      console.log(`Swagger UI: http://localhost:${PORT}/api-docs`);
      console.log(`OpenAPI JSON: http://localhost:${PORT}/api-docs.json`);
    });
  } catch (err) {
    console.error("Server initialization failed:", err);
    process.exit(1);
  }
}

// ✅ สำคัญ: ถ้ารันเอง local -> listen()
// ✅ ถ้า Vercel เรียก -> export app (ห้าม listen)
if (require.main === module) startLocal();
module.exports = app;
