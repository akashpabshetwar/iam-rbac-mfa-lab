const AuditLog = require("../models/AuditLog");

function getIp(req) {
  // handles proxies too (optional)
  const xf = req.headers["x-forwarded-for"];
  if (xf) return String(xf).split(",")[0].trim();
  return req.ip || req.connection?.remoteAddress || null;
}

async function audit(req, { action, outcome, statusCode, target = {}, meta = {} }) {
  try {
    const actorUserId = req.user?.id || null;
    const actorEmail = req.user?.email || null;

    await AuditLog.create({
      actorUserId,
      actorEmail,
      action,
      outcome,
      statusCode,
      ip: getIp(req),
      userAgent: req.headers["user-agent"] || null,
      target,
      meta,
    });
  } catch (e) {
    // IMPORTANT: never break the API if logging fails
    console.error("⚠️ Audit log write failed:", e.message);
  }
}

module.exports = { audit };
