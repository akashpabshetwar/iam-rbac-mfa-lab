require("dotenv").config();
const express = require("express");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const connectDB = require("./config/db");

const app = express();

// Middleware
app.use(cors());
app.use(express.json());
app.use(
  rateLimit({
    windowMs: 60 * 1000,
    max: 100,
  })
);

// Routes (Auth)
const authRoutes = require("./routes/auth.routes");
app.use("/auth", authRoutes);

const meRoutes = require("./routes/me.routes");
app.use(meRoutes);

const adminRoutes = require("./routes/admin.routes");
app.use("/admin", adminRoutes);

const adminAuditRoutes = require("./routes/admin.audit.routes");
app.use("/admin", adminAuditRoutes);

// Health check
app.get("/health", (req, res) => {
  res.json({ status: "OK", service: "IAM Backend" });
});

// Start server
async function start() {
  await connectDB();

  const PORT = process.env.PORT || 4000;
  app.listen(PORT, () => {
    console.log(`🚀 IAM API running at http://localhost:${PORT}`);
  });
}

start().catch((err) => {
  console.error("❌ Failed to start server", err);
  process.exit(1);
});
