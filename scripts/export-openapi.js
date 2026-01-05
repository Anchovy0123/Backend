// scripts/export-openapi.js
// ใช้เพื่อ Export OpenAPI spec เป็นไฟล์ openapi.json ให้ frontend ใช้
const fs = require("fs");
const path = require("path");
require("dotenv").config();

const { specs } = require("../swagger");

const outPath = path.join(process.cwd(), "openapi.json");
fs.writeFileSync(outPath, JSON.stringify(specs, null, 2), "utf-8");

console.log("✅ Exported:", outPath);
