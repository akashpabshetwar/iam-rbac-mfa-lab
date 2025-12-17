module.exports = function requirePermission(permission) {
  return (req, res, next) => {
    // req.user comes from your auth middleware
    const perms = req.user?.permissions || [];

    if (!permission) return next();

    if (!perms.includes(permission)) {
      return res.status(403).json({ error: "Forbidden: missing permission" });
    }

    return next();
  };
};
