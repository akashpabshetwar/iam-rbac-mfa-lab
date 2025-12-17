const mongoose = require("mongoose");

const AuditLogSchema = new mongoose.Schema(
  {
    // who performed it (optional for unauth events like failed login)
    actorUserId: { type: mongoose.Schema.Types.ObjectId, ref: "User", default: null },
    actorEmail: { type: String, default: null },

    // what happened
    action: { type: String, required: true },          // e.g. "auth.login.success"
    outcome: { type: String, required: true },         // "success" | "failure"
    statusCode: { type: Number, default: null },

    // request context
    ip: { type: String, default: null },
    userAgent: { type: String, default: null },

    // target / extra details (never store passwords/tokens/otp)
    target: {
      type: Object,
      default: {},                                     // e.g. { userId, email, route }
    },
    meta: { type: Object, default: {} },               // extra safe metadata
  },
  { timestamps: true }
);

module.exports = mongoose.model("AuditLog", AuditLogSchema);
