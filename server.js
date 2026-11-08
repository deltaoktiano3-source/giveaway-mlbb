require("dotenv").config();
const express = require("express");
const helmet = require("helmet");
const session = require("express-session");
const SQLiteStore = require("connect-sqlite3")(session);
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const rateLimit = require("express-rate-limit");
const nodemailer = require("nodemailer");
const crypto = require("crypto");
const path = require("path");

const app = express();
const isProd = process.env.NODE_ENV === "production";
const port = Number(process.env.PORT || 3000);

if (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32 ||
    process.env.SESSION_SECRET.startsWith("replace-")) {
  throw new Error("Set SESSION_SECRET to a unique random value of at least 32 characters.");
}
if (!process.env.ADMIN_EMAIL || !process.env.ADMIN_PASSWORD ||
    process.env.ADMIN_PASSWORD.startsWith("change-this")) {
  throw new Error("Set ADMIN_EMAIL and a unique ADMIN_PASSWORD in .env before starting.");
}
if (isProd && (!process.env.HCAPTCHA_SECRET || !process.env.HCAPTCHA_SITEKEY)) {
  throw new Error("Production requires HCAPTCHA_SECRET and HCAPTCHA_SITEKEY.");
}
if (isProd) app.set("trust proxy", 1);

const db = new Database(path.join(__dirname, "data.sqlite"));
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");
db.exec(`
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 email TEXT NOT NULL UNIQUE COLLATE NOCASE,
 password_hash TEXT NOT NULL,
 role TEXT NOT NULL DEFAULT 'user',
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS giveaways (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 name TEXT NOT NULL,
 level INTEGER NOT NULL DEFAULT 1,
 heroes INTEGER NOT NULL DEFAULT 0,
 skins INTEGER NOT NULL DEFAULT 0,
 rank TEXT NOT NULL,
 description TEXT NOT NULL DEFAULT '',
 image_url TEXT NOT NULL DEFAULT '',
 status TEXT NOT NULL DEFAULT 'available',
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS claims (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 user_id INTEGER NOT NULL REFERENCES users(id),
 giveaway_id INTEGER NOT NULL REFERENCES giveaways(id),
 status TEXT NOT NULL DEFAULT 'pending',
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 UNIQUE(user_id, giveaway_id)
);
`);

const adminEmail = process.env.ADMIN_EMAIL.trim().toLowerCase();
const adminExists = db.prepare("SELECT id FROM users WHERE email=?").get(adminEmail);
if (!adminExists) {
  const hash = bcrypt.hashSync(process.env.ADMIN_PASSWORD, 12);
  db.prepare("INSERT INTO users(email,password_hash,role) VALUES(?,?, 'admin')").run(adminEmail, hash);
  console.log("Admin account created from environment configuration.");
}

if (db.prepare("SELECT COUNT(*) AS n FROM giveaways").get().n === 0) {
  const add = db.prepare("INSERT INTO giveaways(name,level,heroes,skins,rank,description,status) VALUES(?,?,?,?,?,?,?)");
  add.run("Contoh Akun Kolektor", 45, 38, 24, "Epic", "Contoh data hadiah. Ganti dengan hadiah yang benar-benar tersedia.", "available");
  add.run("Contoh Akun Petualang", 62, 57, 41, "Legend", "Contoh data hadiah. Ganti dengan hadiah yang benar-benar tersedia.", "available");
}

app.use(helmet({ contentSecurityPolicy: {
  directives: {
    defaultSrc: ["'self'"], scriptSrc: ["'self'"], styleSrc: ["'self'", "'unsafe-inline'"],
    imgSrc: ["'self'", "data:", "https:"], connectSrc: ["'self'"], objectSrc: ["'none'"],
    upgradeInsecureRequests: isProd ? [] : null
  }
}}));
app.use(express.json({ limit: "20kb" }));
app.use(express.urlencoded({ extended: false, limit: "20kb" }));
app.use(session({
  store: new SQLiteStore({ db: "sessions.sqlite", dir: __dirname }),
  name: "mlbb.sid",
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, secure: isProd, sameSite: "lax", maxAge: 1000 * 60 * 60 * 8 }
}));

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 10, standardHeaders: true, legacyHeaders: false });
const claimLimiter = rateLimit({ windowMs: 60 * 60 * 1000, limit: 15, standardHeaders: true, legacyHeaders: false });

function csrfToken(req) {
  if (!req.session.csrf) req.session.csrf = crypto.randomBytes(32).toString("hex");
  return req.session.csrf;
}
app.get("/api/csrf", (req, res) => res.json({ csrfToken: csrfToken(req) }));
function requireCsrf(req, res, next) {
  const token = req.get("x-csrf-token");
  if (!token || !req.session.csrf || !crypto.timingSafeEqual(Buffer.from(token), Buffer.from(req.session.csrf))) {
    return res.status(403).json({ error: "Permintaan tidak valid. Muat ulang halaman." });
  }
  next();
}
function requireUser(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: "Silakan login terlebih dahulu." });
  next();
}
function requireAdmin(req, res, next) {
  if (!req.session.user || req.session.user.role !== "admin") return res.status(403).json({ error: "Akses admin diperlukan." });
  next();
}
function validEmail(email) {
  return typeof email === "string" && email.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}
async function verifyCaptcha(token, remoteip) {
  if (!process.env.HCAPTCHA_SECRET) return !isProd; // local development only
  if (!token) return false;
  const body = new URLSearchParams({ secret: process.env.HCAPTCHA_SECRET, response: token });
  if (remoteip) body.set("remoteip", remoteip);
  const response = await fetch("https://hcaptcha.com/siteverify", { method: "POST", body });
  const result = await response.json();
  return result.success === true;
}
async function sendAdminNotice(subject, message) {
  if (!process.env.SMTP_HOST || !process.env.SMTP_USER || !process.env.SMTP_PASS) return;
  const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST, port: Number(process.env.SMTP_PORT || 587),
    secure: Number(process.env.SMTP_PORT) === 465,
    auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
  });
  await transporter.sendMail({
    from: process.env.SMTP_FROM || process.env.SMTP_USER,
    to: adminEmail, subject, text: message
  });
}

app.get("/api/me", (req, res) => {
  res.json({ user: req.session.user ? { id: req.session.user.id, email: req.session.user.email, role: req.session.user.role } : null });
});
app.post("/api/register", authLimiter, requireCsrf, async (req, res) => {
  const { email, password, captchaToken } = req.body || {};
  if (!validEmail(email) || typeof password !== "string" || password.length < 12 || password.length > 128) {
    return res.status(400).json({ error: "Email tidak valid atau password belum memenuhi syarat (12–128 karakter)." });
  }
  if (!await verifyCaptcha(captchaToken, req.ip)) return res.status(400).json({ error: "Verifikasi CAPTCHA gagal." });
  try {
    const hash = await bcrypt.hash(password, 12);
    const result = db.prepare("INSERT INTO users(email,password_hash) VALUES(?,?)").run(email.trim().toLowerCase(), hash);
    req.session.user = { id: Number(result.lastInsertRowid), email: email.trim().toLowerCase(), role: "user" };
    req.session.csrf = crypto.randomBytes(32).toString("hex");
    await sendAdminNotice("Pendaftaran pengguna baru", `Pendaftaran akun website: ${email.trim().toLowerCase()}\nPassword tidak disertakan.`);
    res.status(201).json({ user: req.session.user, csrfToken: csrfToken(req) });
  } catch (e) {
    if (String(e.code).includes("SQLITE_CONSTRAINT")) return res.status(409).json({ error: "Email sudah terdaftar." });
    console.error(e); res.status(500).json({ error: "Terjadi kesalahan server." });
  }
});
app.post("/api/login", authLimiter, requireCsrf, async (req, res) => {
  const { email, password, captchaToken } = req.body || {};
  if (!validEmail(email) || typeof password !== "string" || password.length > 128) return res.status(400).json({ error: "Data login tidak valid." });
  if (!await verifyCaptcha(captchaToken, req.ip)) return res.status(400).json({ error: "Verifikasi CAPTCHA gagal." });
  const user = db.prepare("SELECT * FROM users WHERE email=?").get(email.trim().toLowerCase());
  if (!user || !await bcrypt.compare(password, user.password_hash)) return res.status(401).json({ error: "Email atau password salah." });
  req.session.regenerate(err => {
    if (err) return res.status(500).json({ error: "Tidak dapat membuat sesi." });
    req.session.user = { id: user.id, email: user.email, role: user.role };
    req.session.csrf = crypto.randomBytes(32).toString("hex");
    res.json({ user: req.session.user, csrfToken: csrfToken(req) });
  });
});
app.post("/api/logout", requireUser, requireCsrf, (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.get("/api/giveaways", (req, res) => {
  const rows = db.prepare("SELECT id,name,level,heroes,skins,rank,description,image_url,status FROM giveaways ORDER BY id DESC").all();
  res.json({ giveaways: rows });
});
app.post("/api/claims", requireUser, claimLimiter, requireCsrf, async (req, res) => {
  const id = Number(req.body && req.body.giveawayId);
  if (!Number.isSafeInteger(id) || id < 1) return res.status(400).json({ error: "Hadiah tidak valid." });
  const gift = db.prepare("SELECT id,name,status FROM giveaways WHERE id=?").get(id);
  if (!gift || gift.status !== "available") return res.status(409).json({ error: "Hadiah tidak tersedia." });
  try {
    const result = db.prepare("INSERT INTO claims(user_id,giveaway_id) VALUES(?,?)").run(req.session.user.id, id);
    await sendAdminNotice("Pengajuan klaim giveaway", `Pengguna ${req.session.user.email} mengajukan klaim untuk hadiah #${id} (${gift.name}).\nStatus: pending.\nTidak ada password atau token yang disertakan.`);
    res.status(201).json({ claimId: Number(result.lastInsertRowid), status: "pending" });
  } catch (e) {
    if (String(e.code).includes("SQLITE_CONSTRAINT")) return res.status(409).json({ error: "Anda sudah mengajukan klaim untuk hadiah ini." });
    console.error(e); res.status(500).json({ error: "Terjadi kesalahan server." });
  }
});
app.get("/api/my-claims", requireUser, (req, res) => {
  const claims = db.prepare(`SELECT c.id,c.status,c.created_at,g.name AS giveaway_name
    FROM claims c JOIN giveaways g ON g.id=c.giveaway_id WHERE c.user_id=? ORDER BY c.id DESC`).all(req.session.user.id);
  res.json({ claims });
});

app.post("/api/admin/giveaways", requireAdmin, requireCsrf, (req, res) => {
  const { name, level, heroes, skins, rank, description, imageUrl } = req.body || {};
  if (typeof name !== "string" || !name.trim() || name.length > 100 ||
      typeof rank !== "string" || !rank.trim() || rank.length > 40 ||
      ![level,heroes,skins].every(n => Number.isInteger(n) && n >= 0 && n <= 1000) ||
      typeof description !== "string" || description.length > 1000 ||
      typeof (imageUrl || "") !== "string" || (imageUrl || "").length > 500 ||
      (imageUrl && !/^https:\/\/[^\s]+$/i.test(imageUrl))) {
    return res.status(400).json({ error: "Data hadiah tidak valid." });
  }
  const info = db.prepare(`INSERT INTO giveaways(name,level,heroes,skins,rank,description,image_url)
    VALUES(?,?,?,?,?,?,?)`).run(name.trim(),level,heroes,skins,rank.trim(),description,imageUrl || "");
  res.status(201).json({ id: Number(info.lastInsertRowid) });
});
app.patch("/api/admin/giveaways/:id/status", requireAdmin, requireCsrf, (req, res) => {
  const status = req.body && req.body.status;
  if (!["available","reserved","claimed"].includes(status)) return res.status(400).json({ error: "Status tidak valid." });
  const result = db.prepare("UPDATE giveaways SET status=? WHERE id=?").run(status, Number(req.params.id));
  if (!result.changes) return res.status(404).json({ error: "Hadiah tidak ditemukan." });
  res.json({ ok: true });
});
app.delete("/api/admin/giveaways/:id", requireAdmin, requireCsrf, (req, res) => {
  const id = Number(req.params.id);
  const used = db.prepare("SELECT COUNT(*) AS n FROM claims WHERE giveaway_id=?").get(id).n;
  if (used) return res.status(409).json({ error: "Hadiah memiliki riwayat klaim; ubah statusnya, jangan hapus." });
  const result = db.prepare("DELETE FROM giveaways WHERE id=?").run(id);
  if (!result.changes) return res.status(404).json({ error: "Hadiah tidak ditemukan." });
  res.json({ ok: true });
});
app.get("/api/admin/claims", requireAdmin, (req, res) => {
  const rows = db.prepare(`SELECT c.id,c.status,c.created_at,u.email,g.name AS giveaway_name
    FROM claims c JOIN users u ON u.id=c.user_id JOIN giveaways g ON g.id=c.giveaway_id
    ORDER BY c.id DESC LIMIT 200`).all();
  res.json({ claims: rows });
});
app.patch("/api/admin/claims/:id", requireAdmin, requireCsrf, (req, res) => {
  const status = req.body && req.body.status;
  if (!["approved","rejected"].includes(status)) return res.status(400).json({ error: "Status tidak valid." });
  const claim = db.prepare("SELECT id,giveaway_id FROM claims WHERE id=?").get(Number(req.params.id));
  if (!claim) return res.status(404).json({ error: "Klaim tidak ditemukan." });
  const update = db.transaction(() => {
    db.prepare("UPDATE claims SET status=? WHERE id=?").run(status, claim.id);
    if (status === "approved") db.prepare("UPDATE giveaways SET status='claimed' WHERE id=?").run(claim.giveaway_id);
  });
  update(); res.json({ ok: true });
});

app.use(express.static(path.join(__dirname, "public")));
app.use((err, req, res, next) => { console.error(err); res.status(500).json({ error: "Terjadi kesalahan server." }); });
app.listen(port, () => console.log(`Giveaway app listening on http://localhost:${port}`));
