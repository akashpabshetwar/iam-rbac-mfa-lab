const jwt = require("jsonwebtoken");
const express = require("express");
const bcrypt = require("bcrypt");
const User = require("../models/User");
const { signAccessToken, signRefreshToken } = require("../services/tokens");
const speakeasy = require("speakeasy");
const qrcode = require("qrcode");
const auth = require("../middleware/auth");
const { audit } = require("../services/audit");

const router = express.Router();

// ✅ Register
router.post("/register", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      await audit(req, {
        action: "auth.register.failure",
        outcome: "failure",
        statusCode: 400,
        target: { email },
        meta: { reason: "missing_fields" },
      });
      return res.status(400).json({ error: "Email and password required" });
    }

    const existing = await User.findOne({ email });
    if (existing) {
      await audit(req, {
        action: "auth.register.failure",
        outcome: "failure",
        statusCode: 409,
        target: { email },
        meta: { reason: "user_exists" },
      });
      return res.status(409).json({ error: "User already exists" });
    }

    const passwordHash = await bcrypt.hash(password, 12);
    const created = await User.create({ email, passwordHash });

    await audit(req, {
      action: "auth.register.success",
      outcome: "success",
      statusCode: 201,
      target: { userId: created._id.toString(), email: created.email },
    });

    return res.status(201).json({ message: "User registered successfully" });
  } catch (err) {
    await audit(req, {
      action: "auth.register.failure",
      outcome: "failure",
      statusCode: 500,
      target: { email: req.body?.email },
      meta: { reason: "server_error" },
    });
    return res.status(500).json({ error: "Registration failed" });
  }
});

// ✅ Login (issues access + refresh). If MFA enabled -> requires otp.
router.post("/login", async (req, res) => {
  try {
    const { email, password, otp } = req.body;

    if (!email || !password) {
      await audit(req, {
        action: "auth.login.failure",
        outcome: "failure",
        statusCode: 400,
        target: { email },
        meta: { reason: "missing_fields" },
      });
      return res.status(400).json({ error: "Email and password required" });
    }

    const user = await User.findOne({ email });
    if (!user) {
      await audit(req, {
        action: "auth.login.failure",
        outcome: "failure",
        statusCode: 401,
        target: { email },
        meta: { reason: "invalid_credentials" },
      });
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) {
      await audit(req, {
        action: "auth.login.failure",
        outcome: "failure",
        statusCode: 401,
        target: { userId: user._id.toString(), email: user.email },
        meta: { reason: "invalid_credentials" },
      });
      return res.status(401).json({ error: "Invalid credentials" });
    }

    // ✅ MFA Enforcement
    if (user.mfaEnabled) {
      if (!otp) {
        await audit(req, {
          action: "auth.login.mfa_required",
          outcome: "failure",
          statusCode: 401,
          target: { userId: user._id.toString(), email: user.email },
        });
        return res
          .status(401)
          .json({ error: "MFA required", mfaRequired: true });
      }

      const okOtp = speakeasy.totp.verify({
        secret: user.mfaSecret,
        encoding: "base32",
        token: otp,
        window: 1,
      });

      if (!okOtp) {
        await audit(req, {
          action: "auth.login.failure",
          outcome: "failure",
          statusCode: 401,
          target: { userId: user._id.toString(), email: user.email },
          meta: { reason: "invalid_otp" },
        });
        return res.status(401).json({ error: "Invalid OTP" });
      }
    }

    // Issue tokens only after password (and MFA if enabled) is verified
    const accessToken = signAccessToken(user);
    const refreshToken = signRefreshToken(user);

    user.refreshTokenHash = await bcrypt.hash(refreshToken, 12);
    user.refreshTokenIssuedAt = new Date();
    await user.save();

    await audit(req, {
      action: "auth.login.success",
      outcome: "success",
      statusCode: 200,
      target: { userId: user._id.toString(), email: user.email },
      meta: { mfaEnabled: !!user.mfaEnabled },
    });

    return res.json({ accessToken, refreshToken });
  } catch (err) {
    await audit(req, {
      action: "auth.login.failure",
      outcome: "failure",
      statusCode: 500,
      target: { email: req.body?.email },
      meta: { reason: "server_error" },
    });
    return res.status(500).json({ error: "Login failed" });
  }
});

// Refresh
router.post("/refresh", async (req, res) => {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken) {
      await audit(req, {
        action: "auth.refresh.failure",
        outcome: "failure",
        statusCode: 400,
        meta: { reason: "missing_refresh_token" },
      });
      return res.status(400).json({ error: "refreshToken required" });
    }

    let payload;
    try {
      payload = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
    } catch {
      await audit(req, {
        action: "auth.refresh.failure",
        outcome: "failure",
        statusCode: 401,
        meta: { reason: "invalid_or_expired_refresh" },
      });
      return res.status(401).json({ error: "Invalid or expired refresh token" });
    }

    if (payload.type !== "refresh") {
      await audit(req, {
        action: "auth.refresh.failure",
        outcome: "failure",
        statusCode: 401,
        meta: { reason: "wrong_token_type" },
      });
      return res.status(401).json({ error: "Invalid refresh token" });
    }

    const user = await User.findById(payload.sub);
    if (!user || !user.refreshTokenHash) {
      await audit(req, {
        action: "auth.refresh.failure",
        outcome: "failure",
        statusCode: 401,
        target: { userId: payload.sub },
        meta: { reason: "refresh_not_allowed" },
      });
      return res.status(401).json({ error: "Refresh not allowed" });
    }

    const ok = await bcrypt.compare(refreshToken, user.refreshTokenHash);
    if (!ok) {
      await audit(req, {
        action: "auth.refresh.failure",
        outcome: "failure",
        statusCode: 401,
        target: { userId: user._id.toString(), email: user.email },
        meta: { reason: "refresh_not_allowed" },
      });
      return res.status(401).json({ error: "Refresh not allowed" });
    }

    // ROTATION: issue new pair + replace stored hash
    const newAccessToken = signAccessToken(user);
    const newRefreshToken = signRefreshToken(user);

    user.refreshTokenHash = await bcrypt.hash(newRefreshToken, 12);
    user.refreshTokenIssuedAt = new Date();
    await user.save();

    await audit(req, {
      action: "auth.refresh.success",
      outcome: "success",
      statusCode: 200,
      target: { userId: user._id.toString(), email: user.email },
    });

    return res.json({
      accessToken: newAccessToken,
      refreshToken: newRefreshToken,
    });
  } catch (err) {
    await audit(req, {
      action: "auth.refresh.failure",
      outcome: "failure",
      statusCode: 500,
      meta: { reason: "server_error" },
    });
    return res.status(500).json({ error: "Refresh failed" });
  }
});

//Logout
router.post("/logout", async (req, res) => {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken) {
      await audit(req, {
        action: "auth.logout.failure",
        outcome: "failure",
        statusCode: 400,
        meta: { reason: "missing_refresh_token" },
      });
      return res.status(400).json({ error: "refreshToken required" });
    }

    let payload;
    try {
      payload = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
    } catch {
      // Even if token is bad, treat as logged out (don’t leak info)
      await audit(req, {
        action: "auth.logout.success",
        outcome: "success",
        statusCode: 200,
        meta: { note: "bad_refresh_treated_as_logged_out" },
      });
      return res.json({ message: "Logged out" });
    }

    const user = await User.findById(payload.sub);
    if (user) {
      user.refreshTokenHash = null;
      user.refreshTokenIssuedAt = null;
      await user.save();

      await audit(req, {
        action: "auth.logout.success",
        outcome: "success",
        statusCode: 200,
        target: { userId: user._id.toString(), email: user.email },
      });
    } else {
      await audit(req, {
        action: "auth.logout.success",
        outcome: "success",
        statusCode: 200,
        target: { userId: payload.sub },
      });
    }

    return res.json({ message: "Logged out" });
  } catch (err) {
    await audit(req, {
      action: "auth.logout.failure",
      outcome: "failure",
      statusCode: 500,
      meta: { reason: "server_error" },
    });
    return res.status(500).json({ error: "Logout failed" });
  }
});

// ✅ MFA Setup (Generate secret + QR)
router.post("/mfa/setup", auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) {
      await audit(req, {
        action: "mfa.setup.failure",
        outcome: "failure",
        statusCode: 404,
        target: { userId: req.user?.id, email: req.user?.email },
        meta: { reason: "user_not_found" },
      });
      return res.status(404).json({ error: "User not found" });
    }

    const secret = speakeasy.generateSecret({
      name: `IAM RBAC MFA (${user.email})`,
    });

    user.mfaTempSecret = secret.base32;
    await user.save();

    const qrDataUrl = await qrcode.toDataURL(secret.otpauth_url);

    await audit(req, {
      action: "mfa.setup.started",
      outcome: "success",
      statusCode: 200,
      target: { userId: user._id.toString(), email: user.email },
    });

    return res.json({
      otpauth_url: secret.otpauth_url,
      qrDataUrl,
      message:
        "Scan QR in Google Authenticator, then verify using /auth/mfa/verify",
    });
  } catch (err) {
    await audit(req, {
      action: "mfa.setup.failure",
      outcome: "failure",
      statusCode: 500,
      target: { userId: req.user?.id, email: req.user?.email },
      meta: { reason: "server_error" },
    });
    return res.status(500).json({ error: "MFA setup failed" });
  }
});

// ✅ MFA Verify (Enable MFA after verifying OTP)
router.post("/mfa/verify", auth, async (req, res) => {
  try {
    const { otp } = req.body;
    if (!otp) {
      await audit(req, {
        action: "mfa.verify.failure",
        outcome: "failure",
        statusCode: 400,
        target: { userId: req.user?.id, email: req.user?.email },
        meta: { reason: "missing_otp" },
      });
      return res.status(400).json({ error: "otp required" });
    }

    const user = await User.findById(req.user.id);
    if (!user || !user.mfaTempSecret) {
      await audit(req, {
        action: "mfa.verify.failure",
        outcome: "failure",
        statusCode: 400,
        target: { userId: req.user?.id, email: req.user?.email },
        meta: { reason: "setup_not_started" },
      });
      return res.status(400).json({ error: "MFA setup not started" });
    }

    const ok = speakeasy.totp.verify({
      secret: user.mfaTempSecret,
      encoding: "base32",
      token: otp,
      window: 1,
    });

    if (!ok) {
      await audit(req, {
        action: "mfa.verify.failure",
        outcome: "failure",
        statusCode: 401,
        target: { userId: user._id.toString(), email: user.email },
        meta: { reason: "invalid_otp" },
      });
      return res.status(401).json({ error: "Invalid OTP" });
    }

    user.mfaSecret = user.mfaTempSecret;
    user.mfaTempSecret = null;
    user.mfaEnabled = true;
    await user.save();

    await audit(req, {
      action: "mfa.enabled",
      outcome: "success",
      statusCode: 200,
      target: { userId: user._id.toString(), email: user.email },
    });

    return res.json({ message: "MFA enabled successfully" });
  } catch (err) {
    await audit(req, {
      action: "mfa.verify.failure",
      outcome: "failure",
      statusCode: 500,
      target: { userId: req.user?.id, email: req.user?.email },
      meta: { reason: "server_error" },
    });
    return res.status(500).json({ error: "MFA verify failed" });
  }
});

module.exports = router;
