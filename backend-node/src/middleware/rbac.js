function requireRole(...allowedRoles) {
  return (req, res, next) => {
    const role = req.user?.role;
    if (!role) return res.status(401).json({ error: "Unauthorized" });

    if (!allowedRoles.includes(role))
      return res.status(403).json({ error: "Forbidden: role not allowed" });

    next();
  };
}

function requirePermission(...requiredPerms) {
  return (req, res, next) => {
    const perms = req.user?.permissions || [];
    const ok = requiredPerms.every((p) => perms.includes(p));
    if (!ok) return res.status(403).json({ error: "Forbidden: missing permission" });
    next();
  };
}

module.exports = { requireRole, requirePermission };
