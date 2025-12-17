const express = require("express");
const User = require("../models/User");
const auth = require("../middleware/auth");
const { requireRole, requirePermission } = require("../middleware/rbac");

const router = express.Router();

// Only admin can view all users
router.get("/users", auth, requireRole("admin"), requirePermission("users:read"), async (req, res) => {
  const users = await User.find({}, { email: 1, role: 1, permissions: 1 });
  res.json({ users });
});

// Only admin can update a user's role
router.patch("/users/:id/role", auth, requireRole("admin"), requirePermission("users:write"), async (req, res) => {
  const { role } = req.body;
  if (!["user", "admin", "auditor"].includes(role))
    return res.status(400).json({ error: "Invalid role" });

  const user = await User.findByIdAndUpdate(
    req.params.id,
    { role },
    { new: true, fields: { email: 1, role: 1 } }
  );

  if (!user) return res.status(404).json({ error: "User not found" });
  res.json({ message: "Role updated", user });
});

// Only admin with users:write can update permissions
router.patch(
  "/users/:id/permissions",
  auth,
  requireRole("admin"),
  requirePermission("users:write"),
  async (req, res) => {
    const { permissions } = req.body;

    if (!Array.isArray(permissions))
      return res.status(400).json({ error: "permissions must be an array" });

    // Optional: basic format check
    const bad = permissions.find((p) => typeof p !== "string" || !p.includes(":"));
    if (bad) return res.status(400).json({ error: "Invalid permission format" });

    const user = await User.findByIdAndUpdate(
      req.params.id,
      { permissions },
      { new: true, fields: { email: 1, role: 1, permissions: 1 } }
    );

    if (!user) return res.status(404).json({ error: "User not found" });

    return res.json({ message: "Permissions updated", user });
  }
);

module.exports = router;
