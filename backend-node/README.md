    # 🔐 IAM RBAC + MFA System (Node.js & MongoDB)

A production-style **Identity and Access Management (IAM)** system built from scratch using **Node.js, Express, MongoDB, JWT, RBAC, MFA (TOTP)** and **audit logging**.

This project demonstrates real-world security controls including:
- Secure authentication (JWT)
- Role-Based Access Control (RBAC)
- Permission-based authorization
- Multi-Factor Authentication (Google Authenticator – TOTP)
- Refresh token rotation & logout
- Centralized audit logging

## 🧰 Tech Stack
| Layer | Technology |
|-----|-----------|
Backend | Node.js (Express)
Database | MongoDB 7 (Docker)
Authentication | JWT (jsonwebtoken)
Authorization | RBAC + Permissions
Password Hashing | bcrypt
Multi-Factor Auth | speakeasy (TOTP) + qrcode
Audit Logging | MongoDB (AuditLog collection)
Rate Limiting | express-rate-limit
Dev Tools | nodemon, dotenv
OS | Windows 11 (Local Development)

## 🏗️ Architecture Overview

This backend follows a clean, production-style structure:

- **Routes** handle HTTP endpoints (`/auth`, `/me`, `/admin`)
- **Middleware** enforces authentication and authorization (JWT + permissions)
- **Services** contain reusable logic (token signing, audit logging)
- **MongoDB** stores users, refresh token hashes, and audit logs

### Request Flow (High Level)

1. Client calls **/auth/login**
2. Server validates password (and **TOTP** if MFA is enabled)
3. Server issues **Access Token (short-lived)** + **Refresh Token (rotating)**
4. Client calls protected APIs using:
   - `Authorization: Bearer <accessToken>`
5. Authorization checks enforce:
   - **role-based** access (admin/user)
   - **permission-based** rules (ex: `users:read`, `audit:read`)
6. Important security events are written to the **AuditLog** collection

## 🚀 Run Locally (Windows)

### 1) Start MongoDB (Docker)
```bat
docker run -d -p 27017:27017 --name iam-mongo mongo:7
docker ps


2. Create a .env file inside backend-node/:
PORT=4000
MONGO_URI=mongodb://localhost:27017/iam_lab

JWT_ACCESS_SECRET=dev_access_secret_change_later
JWT_REFRESH_SECRET=dev_refresh_secret_change_later

ACCESS_TOKEN_TTL=15m
REFRESH_TOKEN_TTL_DAYS=7

3.Install Dependencies
cd backend-node
npm install

4. Start the API (Dev Mode)
npm run dev

5.Expected output:
✅ MongoDB connected
🚀 IAM API running at http://localhost:4000

6.Health Check
curl http://localhost:4000/health

## 🔌 API Endpoints + curl Examples (Windows CMD)

> **Tip (Windows CMD):** For multi-line curl, use `^` at the end of each line.  
> Keep your API running (`npm run dev`) in a separate terminal.

---

### ✅ Health
```bat
curl http://localhost:4000/health


1. Auth — Register
curl -X POST http://localhost:4000/auth/register ^
  -H "Content-Type: application/json" ^
  -d "{\"email\":\"user1@test.com\",\"password\":\"StrongPass123\"}"

2.Authentication — Login (No MFA)
curl -X POST http://localhost:4000/auth/login ^
  -H "Content-Type: application/json" ^
  -d "{\"email\":\"user1@test.com\",\"password\":\"StrongPass123\"}"

3.MFA — Setup (Generate QR Code)
curl -X POST http://localhost:4000/auth/mfa/setup ^
  -H "Authorization: Bearer PASTE_ACCESS_TOKEN_HERE"

4.MFA — Verify (Enable MFA)
curl -X POST http://localhost:4000/auth/mfa/verify ^
  -H "Content-Type: application/json" ^
  -H "Authorization: Bearer PASTE_ACCESS_TOKEN_HERE" ^
  -d "{\"otp\":\"123456\"}"

5.Authentication — Login (MFA Enabled)
curl -X POST http://localhost:4000/auth/login ^
  -H "Content-Type: application/json" ^
  -d "{\"email\":\"user1@test.com\",\"password\":\"StrongPass123\",\"otp\":\"123456\"}"

6.Token Refresh (Rotation)
curl -X POST http://localhost:4000/auth/refresh ^
  -H "Content-Type: application/json" ^
  -d "{\"refreshToken\":\"PASTE_REFRESH_TOKEN_HERE\"}"

7.Logout (Invalidate Refresh Token)
curl -X POST http://localhost:4000/auth/logout ^
  -H "Content-Type: application/json" ^
  -d "{\"refreshToken\":\"PASTE_REFRESH_TOKEN_HERE\"}"

8.Admin — List Users (RBAC Protected)
curl http://localhost:4000/admin/users ^
  -H "Authorization: Bearer PASTE_ACCESS_TOKEN_HERE"

9.Admin — View Audit Logs
curl http://localhost:4000/admin/audit ^
  -H "Authorization: Bearer PASTE_ACCESS_TOKEN_HERE"

## 🔐 Security Design & Controls

This IAM system is designed using **defense-in-depth** and **least-privilege** principles commonly used in enterprise security architectures.

### Authentication Security
- Passwords are hashed using **bcrypt** (adaptive hashing)
- No plaintext passwords, tokens, or OTPs are stored
- JWT **Access Tokens** are short-lived
- JWT **Refresh Tokens** are rotated and stored only as **bcrypt hashes**
- Logout immediately invalidates refresh capability

### Multi-Factor Authentication (MFA)
- Uses **TOTP (RFC 6238)** compatible with Google Authenticator
- MFA secrets are generated server-side
- MFA enrollment requires verification before activation
- MFA is enforced on login once enabled
- OTP values are **never logged or stored**

### Authorization (RBAC + Permissions)
- Role-based access (`user`, `admin`)
- Fine-grained permission checks (`users:read`, `audit:read`)
- Authorization enforced via middleware
- Permissions embedded into JWT claims for stateless validation

### Audit Logging
- Centralized audit logging for security-relevant events
- Captures:
  - Action performed
  - Outcome (success/failure)
  - HTTP status code
  - IP address
  - User agent
  - Target user (when applicable)
- Logs are **write-only** from application logic
- Audit access restricted to admin users with `audit:read`

### Additional Protections
- Rate limiting enabled for API endpoints
- Generic authentication error messages to prevent user enumeration
- Separation of concerns across routes, middleware, services, and models


## 📋 Audit Logging

This project implements **security-grade audit logging** aligned with SOC 2 / ISO 27001 expectations.

Audit logs are written for **authentication, authorization, and session-related events** and stored in a dedicated MongoDB collection.

### Events Logged
- Successful and failed logins
- MFA setup and MFA enablement
- Invalid OTP attempts
- Refresh token failures
- Logout events
- Admin access to protected resources

### Audit Log Fields
Each audit record captures:

- `action` — logical event name (e.g. `auth.login.success`)
- `outcome` — `success` or `failure`
- `statusCode` — HTTP status code
- `actorUserId` — user performing the action (if authenticated)
- `actorEmail` — email of the actor (if available)
- `ip` — client IP address
- `userAgent` — client user agent
- `target` — affected resource or user
- `meta` — safe contextual metadata (never secrets)
- `createdAt` — timestamp

### Example Audit Actions
- `auth.login.success`
- `auth.login.failure`
- `auth.login.mfa_required`
- `auth.refresh.failure`
- `mfa.enabled`
- `auth.logout`

### Access Control
- Audit logs are **read-only**
- Only users with:
  - `admin` role
  - `audit:read` permission  
  can access audit data via:


### Security Notes
- No passwords, tokens, OTPs, or secrets are logged
- Audit failures never block API functionality
- Logs are designed for forensic analysis and compliance review

## 📁 Project Structure (Summary)

backend-node/
├── src/
│ ├── app.js # Express app bootstrap
│ ├── config/
│ │ └── db.js # MongoDB connection
│ ├── middleware/
│ │ ├── auth.js # JWT authentication
│ │ ├── requireRole.js # Role-based access control
│ │ └── requirePermission.js# Permission-based authorization
│ ├── models/
│ │ ├── User.js # User identity model
│ │ └── AuditLog.js # Security audit logs
│ ├── routes/
│ │ ├── auth.routes.js # Auth, MFA, refresh, logout
│ │ ├── admin.routes.js # Admin user management
│ │ └── admin.audit.routes.js # Audit log access
│ └── services/
│ ├── tokens.js # JWT signing logic
│ └── audit.js # Centralized audit logger
├── .env
└── README.md


---

## 🚀 Future Enhancements

These improvements can be added without changing the core architecture:

- Encrypt MFA secrets at rest
- Account lockout after repeated failed logins
- Audit log filtering (by user, action, date)
- Audit export to CSV/JSON (Python tooling)
- Session revocation dashboard
- Frontend UI (React / Angular)
- OAuth / SSO integration

---

## 🎯 What This Project Demonstrates

This project demonstrates **real-world IAM engineering skills**, including:

- Secure authentication lifecycle design
- MFA enforcement using industry standards
- RBAC and permission-based authorization
- Token rotation and session invalidation
- Audit logging aligned with compliance requirements
- Clean backend architecture and separation of concerns

This mirrors IAM systems used in:
- SaaS platforms
- Enterprise dashboards
- Cloud security tooling
- Internal admin portals

---

## 👤 Author

**Akash Pabshetwar**  
Focus Areas: IAM · Application Security · Cloud Security · SOC Operations

---

## ⭐ Notes

If you find this project useful, feel free to star the repository or fork it for learning purposes..
