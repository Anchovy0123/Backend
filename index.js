require("dotenv").config({
  path:
    process.env.DOTENV_CONFIG_PATH ||
    (process.env.NODE_ENV === "production" ? ".env.production" : ".env.local"),
  override: true, // ✅ สำคัญ: ให้ทับ env ที่ค้างอยู่
});

const express = require("express");
const cors = require("cors");
const db = require("./config/db");
const { swaggerUi, specs } = require("./swagger");

const app = express();
app.use(cors());
app.use(express.json());

/**
 * @openapi
 * /ping:
 *   get:
 *     tags: [Health]
 *     summary: Ping database (returns server time)
 *     responses:
 *       200:
 *         description: OK
 */
app.get("/ping", async (req, res) => {
  try {
    const [rows] = await db.query("SELECT NOW() AS now");
    return res.json({ status: "ok", time: rows[0].now });
  } catch (err) {
    console.error("GET /ping error:", err);
    return res.status(500).json({ error: "Database error" });
  }
});

// Routes
app.use("/api/users", require("./routes/users"));
app.use("/api/login", require("./routes/login"));

// Swagger UI + JSON spec export
app.get("/api-docs.json", (req, res) => res.json(specs));
app.use(
  "/api-docs",
  swaggerUi.serve,
  swaggerUi.setup(specs, {
    explorer: true,
    swaggerOptions: { persistAuthorization: true },
  })
);

async function initializeSchema() {
  const createUsersTableSQL = `
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
  await db.query(createUsersTableSQL);
}

async function startServer() {
  const PORT = process.env.PORT || 3000;

  // ✅ แนะนำ: ให้ server ติดแม้ DB จะมีปัญหา (เพื่อเข้า Swagger ได้ก่อน)
  try {
    await initializeSchema();
    console.log("DB connected & schema ready");
  } catch (err) {
    console.error("⚠️ DB init failed (server will still start):", err.message);
  }

  app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
    console.log(`Swagger UI: http://localhost:${PORT}/api-docs`);
    console.log(`OpenAPI JSON: http://localhost:${PORT}/api-docs.json`);
  });
}

startServer();
