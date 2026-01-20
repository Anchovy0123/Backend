const jwt = require("jsonwebtoken");

const COOKIE_NAME = "auth_token";

const parseCookies = (cookieHeader) => {
  const list = {};
  if (!cookieHeader) return list;

  const pairs = cookieHeader.split(";");
  for (const pair of pairs) {
    const index = pair.indexOf("=");
    if (index < 0) continue;
    const key = pair.slice(0, index).trim();
    const rawValue = pair.slice(index + 1).trim();
    if (!key) continue;
    try {
      list[key] = decodeURIComponent(rawValue);
    } catch (err) {
      list[key] = rawValue;
    }
  }
  return list;
};

const authMiddleware = (req, res, next) => {
  const secret = process.env.JWT_SECRET;
  if (!secret) {
    return res.status(500).json({ error: "Server misconfigured" });
  }

  const cookies = parseCookies(req.headers.cookie);
  const token = cookies[COOKIE_NAME];
  if (!token) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  try {
    const payload = jwt.verify(token, secret);
    req.user = payload;
    return next();
  } catch (err) {
    return res.status(401).json({ error: "Invalid token" });
  }
};

module.exports = { authMiddleware, COOKIE_NAME };
