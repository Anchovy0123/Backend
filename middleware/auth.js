const jwt = require("jsonwebtoken");

// อ่าน token จาก header: Authorization: Bearer <token>
module.exports = function verifyToken(req, res, next) {
  try {
    const authHeader = String(req.headers.authorization || "");
    const token = authHeader.startsWith("Bearer ")
      ? authHeader.slice(7).trim()
      : "";

    if (!token) {
      return res.status(401).json({ error: "Missing token" });
    }

    const SECRET_KEY = process.env.SECRET_KEY || process.env.JWT_SECRET;
    if (!SECRET_KEY) {
      return res.status(500).json({ error: "Server missing SECRET_KEY" });
    }

    const decoded = jwt.verify(token, SECRET_KEY);
    req.user = decoded; // { role, id ... } หรือ { customer_id ... }
    next();
  } catch (err) {
    return res.status(401).json({ error: "Invalid token" });
  }
};
