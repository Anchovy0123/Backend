// middleware/auth.js
const jwt = require("jsonwebtoken");

const SECRET_KEY = process.env.SECRET_KEY || process.env.JWT_SECRET;

function verifyToken(req, res, next) {
  // อ่าน header Authorization (รองรับทั้งตัวเล็ก/ใหญ่)
  const authHeader = req.headers["authorization"] || req.headers["Authorization"];

  // ไม่ส่ง header มาเลย → 401 Unauthorized
  if (!authHeader) {
    return res.status(401).json({
      status: 401,
      error: "Unauthorized",        // ❌ ไม่มี token
    });
  }

  // รูปแบบต้องเป็น "Bearer <token>"
  const parts = authHeader.split(" ");
  if (parts.length !== 2 || parts[0] !== "Bearer") {
    return res.status(401).json({
      status: 401,
      error: "Unauthorized",        // ❌ รูปแบบ header ไม่ถูกต้อง
    });
  }

  const token = parts[1];

  // ตรวจสอบ token ด้วย jwt.verify()
  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err) {
      return res.status(401).json({
        status: 401,
        error: "Unauthorized",      // ❌ token หมดอายุ / ปลอม / ใช้ key ไม่ตรง
      });
    }

    // ✅ ผ่าน: เก็บ payload จาก token ไว้ใช้ต่อใน req.user
    req.user = decoded;
    next();
  });
}

module.exports = verifyToken;
