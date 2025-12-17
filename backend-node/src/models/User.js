const mongoose = require("mongoose");

const UserSchema = new mongoose.Schema(
  {
    email: { type: String, unique: true, required: true, lowercase: true },
    passwordHash: { type: String, required: true },
    refreshTokenHash: { type: String, default: null },
    refreshTokenIssuedAt: { type: Date, default: null },
    mfaEnabled: { type: Boolean, default: false },
    mfaSecret: { type: String, default: null },       // base32 secret (encrypt in prod)
    mfaTempSecret: { type: String, default: null },   // during setup before verify
    roles: [{ type: mongoose.Schema.Types.ObjectId, ref: "Role" }],
    role: { type: String, enum: ["user", "admin", "auditor"], default: "user" },
    permissions: { type: [String], default: [] } // optional fine-grained perms

  },
  { timestamps: true }
);

module.exports = mongoose.model("User", UserSchema);
