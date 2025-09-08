//
// Minimal Payment Tracking Portal (con logo en header y página de inicio)
// Stack: Node.js + Express + better-sqlite3 + EJS-like HTML

const express = require("express");
const session = require("express-session");
const SQLite = require("better-sqlite3");
const bcrypt = require("bcrypt");
const helmet = require("helmet");
const csrf = require("csurf");
const { nanoid } = require("nanoid");
const path = require("path");

const app = express();
const db = new SQLite(path.join(__dirname, "tracker.db"));

app.use(helmet());
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(
  session({
    secret: process.env.SESSION_SECRET || "replace_this_with_env_secret",
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true, sameSite: "lax" },
  })
);
app.use(csrf());

// NEW: servir archivos estáticos (logo, css, etc.)
app.use(express.static(path.join(__dirname, "public")));

// ---------- DB bootstrap ----------
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  email TEXT UNIQUE NOT NULL,
  project TEXT,
  status TEXT NOT NULL DEFAULT 'NO INICIADA',
  access_code_hash TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS admins (
  id TEXT PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  admin_email TEXT NOT NULL,
  from_status TEXT,
  to_status TEXT NOT NULL,
  at DATETIME DEFAULT CURRENT_TIMESTAMP
);
`);

// Seed admin if missing
const adminEmail = "admin@local";
const adminPass = "Admin123!";
const hasAdmin = db.prepare("SELECT 1 FROM admins LIMIT 1").get();
if (!hasAdmin) {
  const hash = bcrypt.hashSync(adminPass, 10);
  db.prepare("INSERT INTO admins (id,email,password_hash) VALUES (?,?,?)")
    .run(nanoid(), adminEmail, hash);
  console.log(`> Admin creado: ${adminEmail} / ${adminPass} (cámbialo en /admin)`);
}

// ---------- Helpers ----------
const STATUSES = [
  "NO INICIADA",
  "RECIBO EMITIDO",
  "CCF RECIBIDO",
  "CHEQUE LISTO",
  "TRANSFERENCIA REALIZADA",
];

function requireAdmin(req, res, next) {
  if (req.session?.admin) return next();
  return res.redirect("/admin/login");
}
function requireUser(req, res, next) {
  if (req.session?.userId) return next();
  return res.redirect("/login");
}

function layout(title, body, { csrfToken, admin, user } = {}) {
  return `<!doctype html>
<html lang="es"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${title}</title>
<style>
  body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;margin:0;background:#f6f7fb;color:#111}
  header,footer{padding:12px 16px;background:#fff;border-bottom:1px solid #eee;display:flex;align-items:center}
  header img{height:32px;margin-right:8px}
  main{max-width:1000px;margin:24px auto;padding:0 16px}
  .card{background:#fff;border:1px solid #eee;border-radius:12px;padding:16px;margin:12px 0}
  input,select,button{font:inherit;padding:8px;border-radius:8px;border:1px solid #ccc}
  table{width:100%;border-collapse:collapse}
  th,td{padding:8px;border-bottom:1px solid #eee;text-align:left}
  .row{display:flex;gap:12px;flex-wrap:wrap}
  .pill{display:inline-block;padding:4px 10px;border-radius:999px;font-weight:600}
  .s1{background:#eee}
  .ok{background:#d1fae5;color:#065f46}
  .warn{background:#fef3c7;color:#92400e}
  .bad{background:#fee2e2;color:#991b1b}
  .btn{background:#111;color:#fff;border:none;cursor:pointer}
  .btn.outline{background:#fff;color:#111;border:1px solid #111}
  .topbar-right{margin-left:auto}
  .muted{color:#666}
  .w100{width:100%}
  form{margin:0}
  .center{text-align:center}
</style>
</head>
<body>
<header class="topbar">
  <img src="/logo.png" alt="Logo">
  <strong>Portal Pagos</strong>
  <span class="topbar-right">
    ${admin
      ? `<span class="muted">Admin: ${admin}</span> <a href="/signout">Salir</a>`
      : user
      ? `<a href="/me">Mi estado</a> <a href="/signout">Salir</a>`
      : `<a href="/login">Ingresar</a>`}
  </span>
</header>
<main>
${body}
</main>
<footer><small class="muted">© ${new Date().getFullYear()} — Tracking Pagos</small></footer>
</body></html>`;
}

function statusPill(s) {
  const map = {
    "NO INICIADA":"bad",
    "RECIBO EMITIDO":"warn",
    "CCF RECIBIDO":"s1",
    "CHEQUE LISTO":"s1",
    "TRANSFERENCIA REALIZADA":"ok",
  };
  const cls = map[s] || "s1";
  return `<span class="pill ${cls}">${s}</span>`;
}

// ---------- Public ----------
app.get("/", (req, res) => {
  res.send(layout("Inicio", `
    <div class="card center">
      <img src="/logo.png" alt="Logo" style="max-height:80px;margin-bottom:16px;">
      <h2>Seguimiento de pago</h2>
      <p>Ingresa con tu correo y código para ver tu estado.</p>
      <div class="row center" style="justify-content:center">
        <a class="btn" href="/login">Ingresar</a>
        <a class="btn outline" href="/admin">Panel Admin</a>
      </div>
    </div>
  `, { admin: req.session.admin, user: req.session.userId }));
});

// ... resto del código idéntico al que ya tenías, incluyendo rutas de login, admin, etc.
// IMPORTANTE: las rutas de /signout y el handler 404 siguen incluidas como antes.

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`> Running at http://localhost:${PORT}`));
