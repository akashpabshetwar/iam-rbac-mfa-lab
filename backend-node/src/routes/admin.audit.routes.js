const express = require("express");
const AuditLog = require("../models/AuditLog");
const auth = require("../middleware/auth");
const requirePermission = require("../middleware/requirePermission");

const router = express.Router();

// View audit logs (needs audit:read)
router.get("/audit", auth, requirePermission("audit:read"), async (req, res) => {
  const logs = await AuditLog.find().sort({ createdAt: -1 }).limit(200);
  res.json({ logs });
});

module.exports = router;
