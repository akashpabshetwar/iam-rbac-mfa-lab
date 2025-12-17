const jwt = require("jsonwebtoken");

function signAccessToken(user) {
  const payload = {
    sub: user._id.toString(),
    email: user.email,
    role: user.role,                     // ✅ RBAC
    permissions: user.permissions || [], // ✅ fine-grained permissions
  };

  return jwt.sign(payload, process.env.JWT_ACCESS_SECRET, {
    expiresIn: process.env.ACCESS_TOKEN_TTL || "15m",
  });
}

function signRefreshToken(user) {
  const days = process.env.REFRESH_TOKEN_TTL_DAYS || "7";

  return jwt.sign(
    {
      sub: user._id.toString(),
      type: "refresh",
    },
    process.env.JWT_REFRESH_SECRET,
    { expiresIn: `${days}d` }
  );
}

module.exports = { signAccessToken, signRefreshToken };
