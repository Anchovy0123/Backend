// /index.js
require("dotenv").config({
  path:
    process.env.DOTENV_CONFIG_PATH ||
    (process.env.NODE_ENV === "production" ? ".env.production" : ".env.local"),
  override: true,
});

const express = require("express");
const cors = require("cors");

const db = require("./config/db");
const { swaggerUi, specs } = require("./swagger");

const app = express();
app.use(cors());
app.use(express.json());

// ---- Swagger entry (Vercel root) ----
app.get("/", (req, res) => {
  res.type("html").send(`<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Backend API</title>
    <style>
      :root { color-scheme: light; }
      body {
        margin: 0;
        font-family: "Segoe UI", Tahoma, Arial, sans-serif;
        background: linear-gradient(140deg, #f8fafc, #e2e8f0);
        color: #0f172a;
      }
      .wrap {
        min-height: 100vh;
        display: grid;
        place-items: center;
        padding: 24px;
      }
      .card {
        background: #ffffff;
        border-radius: 16px;
        padding: 28px 32px;
        box-shadow: 0 10px 30px rgba(15, 23, 42, 0.12);
        max-width: 520px;
        width: 100%;
      }
      h1 { margin: 0 0 8px; font-size: 24px; }
      p { margin: 0 0 18px; color: #475569; }
      .btn {
        display: inline-block;
        background: #0f172a;
        color: #ffffff;
        padding: 12px 18px;
        border-radius: 10px;
        text-decoration: none;
        font-weight: 600;
      }
      .links { margin-top: 12px; font-size: 14px; }
      .links a { color: #0f172a; text-decoration: none; margin-right: 12px; }
    </style>
  </head>
  <body>
    <div class="wrap">
      <div class="card">
        <h1>Backend API</h1>
        <p>Use the button below to open the Swagger UI.</p>
        <a class="btn" href="/api-docs">Open API Docs</a>
        <div class="links">
          <a href="/api-docs.json">OpenAPI JSON</a>
          <a href="/ping">Health Check</a>
        </div>
      </div>
    </div>
  </body>
</html>`);
});

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
app.use("/api/users", require("./routes/users"));

const loginRouter = require("./routes/login");
app.use("/api/login", loginRouter);
app.use("/api/auth", loginRouter);

// ---- Swagger ----
app.get("/api-docs.json", (req, res) => res.json(specs));

const CSS_URL =
  "https://cdnjs.cloudflare.com/ajax/libs/swagger-ui/5.0.0/swagger-ui.min.css";

app.use(
  "/api-docs",
  swaggerUi.serve,
  swaggerUi.setup(specs, {
    customCssUrl: CSS_URL,
    customJs: [
      "https://cdnjs.cloudflare.com/ajax/libs/swagger-ui/5.0.0/swagger-ui-bundle.js",
      "https://cdnjs.cloudflare.com/ajax/libs/swagger-ui/5.0.0/swagger-ui-standalone-preset.js",
    ],
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
      address TEXT,
      sex VARCHAR(20),
      birthday DATE,
      status VARCHAR(20) NOT NULL DEFAULT 'active',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
  `;
  await db.query(sql);

  const columnAdds = [
    { name: "address", sql: "ALTER TABLE tbl_users ADD COLUMN address TEXT" },
    { name: "sex", sql: "ALTER TABLE tbl_users ADD COLUMN sex VARCHAR(20)" },
    { name: "birthday", sql: "ALTER TABLE tbl_users ADD COLUMN birthday DATE" },
  ];

  for (const column of columnAdds) {
    try {
      await db.query(column.sql);
    } catch (err) {
      if (err && err.code !== "ER_DUP_FIELDNAME") {
        throw err;
      }
    }
  }
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
