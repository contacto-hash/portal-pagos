//
// Minimal Payment Tracking Portal (versión completa con logout unificado y 404 amigable)
// Stack: Node.js + Express + better-sqlite3 + EJS-like HTML
// Features: Admin CRUD usuarios, actualización de estatus, login por código, audit log.
// Seguridad básica: sesiones, bcrypt, helmet, CSRF.

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
  header,footer{padding:12px 16px;background:#fff;border-bottom:1px solid #eee}
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
  .topbar a{margin-right:12px;text-decoration:none}
  .muted{color:#666}
  .w100{width:100%}
  form{margin:0}
</style>
</head>
<body>
<header class="topbar">
  <strong>Portal Pagos</strong>
  <span style="float:right">
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
    <div class="card">
      <h2>Seguimiento de pago</h2>
      <p>Ingresa con tu correo y código para ver tu estado.</p>
      <div class="row">
        <a class="btn" href="/login">Ingresar</a>
        <a class="btn outline" href="/admin">Panel Admin</a>
      </div>
    </div>
  `, { admin: req.session.admin, user: req.session.userId }));
});

// ---------- User auth ----------
app.get("/login", (req, res) => {
  res.send(layout("Ingresar", `
  <div class="card">
    <h3>Ingreso de usuario</h3>
    <form method="POST" action="/login">
      <input type="hidden" name="_csrf" value="${req.csrfToken()}">
      <div class="row">
        <input class="w100" type="email" name="email" placeholder="tu-correo@ejemplo.com" required>
        <input class="w100" type="password" name="code" placeholder="tu código de acceso" required>
      </div>
      <p class="muted">Tu administrador te entrega un código.</p>
      <button class="btn">Entrar</button>
    </form>
  </div>
  `));
});

app.post("/login", async (req, res) => {
  const { email, code } = req.body;
  const u = db.prepare("SELECT * FROM users WHERE email=?").get(email.trim().toLowerCase());
  if (!u) return res.send(layout("Error", `<div class="card">Usuario no encontrado. <a href="/login">Volver</a></div>`));
  const ok = await bcrypt.compare(code, u.access_code_hash);
  if (!ok) return res.send(layout("Error", `<div class="card">Código incorrecto. <a href="/login">Volver</a></div>`));
  req.session.userId = u.id;
  res.redirect("/me");
});

// ---------- Logout unificado ----------
app.all("/signout", (req, res) => {
  req.session.destroy(() => res.redirect("/"));
});
app.all("/salir", (req, res) => {
  req.session.destroy(() => res.redirect("/"));
});

app.get("/me", requireUser, (req, res) => {
  const u = db.prepare("SELECT name,email,project,status FROM users WHERE id=?").get(req.session.userId);
  if (!u) return res.redirect("/signout");
  res.send(layout("Mi estado", `
    <div class="card">
      <h2>${u.name}</h2>
      <p><strong>Proyecto:</strong> ${u.project || "-"}</p>
      <p><strong>Estatus de pago:</strong> ${statusPill(u.status)}</p>
    </div>
  `, { user: u.email }));
});

// ---------- Admin auth ----------
app.get("/admin/login", (req, res) => {
  res.send(layout("Admin Login", `
  <div class="card">
    <h3>Ingreso Admin</h3>
    <form method="POST" action="/admin/login">
      <input type="hidden" name="_csrf" value="${req.csrfToken()}">
      <div class="row">
        <input class="w100" type="email" name="email" placeholder="admin@local" required>
        <input class="w100" type="password" name="password" placeholder="password" required>
      </div>
      <button class="btn">Entrar</button>
    </form>
  </div>
  `));
});
app.post("/admin/login", async (req, res) => {
  const { email, password } = req.body;
  const a = db.prepare("SELECT * FROM admins WHERE email=?").get(email.trim());
  if (!a) return res.send(layout("Error", `<div class="card">Admin no existe. <a href="/admin/login">Volver</a></div>`));
  const ok = await bcrypt.compare(password, a.password_hash);
  if (!ok) return res.send(layout("Error", `<div class="card">Clave incorrecta. <a href="/admin/login">Volver</a></div>`));
  req.session.admin = a.email;
  res.redirect("/admin");
});
app.get("/admin/logout", (req, res) => { // (queda por compatibilidad, redirige al unificado)
  req.session.destroy(() => res.redirect("/"));
});

// ---------- Admin panel ----------
app.get("/admin", requireAdmin, (req, res) => {
  const users = db.prepare("SELECT id,name,email,project,status FROM users ORDER BY name").all();
  const log = db.prepare("SELECT u.name as user_name, l.* FROM audit_log l JOIN users u ON u.id=l.user_id ORDER BY at DESC LIMIT 20").all();
  res.send(layout("Panel Admin", `
  <div class="card">
    <h3>Usuarios</h3>
    <form method="POST" action="/admin/users/create" class="row">
      <input type="hidden" name="_csrf" value="${req.csrfToken()}">
      <input name="name" placeholder="Nombre completo" required>
      <input type="email" name="email" placeholder="correo@ejemplo.com" required>
      <input name="project" placeholder="Proyecto">
      <input name="code" placeholder="Código de acceso (entregar al usuario)" required>
      <button class="btn">Crear usuario</button>
    </form>
    <table>
      <thead><tr><th>Nombre</th><th>Email</th><th>Proyecto</th><th>Estatus</th><th>Acciones</th></tr></thead>
      <tbody>
        ${users.map(u => `
          <tr>
            <td>${u.name}</td>
            <td>${u.email}</td>
            <td>${u.project||"-"}</td>
            <td>${statusPill(u.status)}</td>
            <td>
              <form method="POST" action="/admin/users/update" class="row" style="gap:6px;align-items:center">
                <input type="hidden" name="_csrf" value="${req.csrfToken()}">
                <input type="hidden" name="id" value="${u.id}">
                <select name="status">
                  ${STATUSES.map(s => `<option value="${s}" ${s===u.status?'selected':''}>${s}</option>`).join("")}
                </select>
                <input name="project" value="${u.project||''}" placeholder="Proyecto">
                <button class="btn">Guardar</button>
              </form>
            </td>
          </tr>
        `).join("")}
      </tbody>
    </table>
  </div>

  <div class="card">
    <h3>Últimos cambios</h3>
    <table>
      <thead><tr><th>Fecha</th><th>Usuario</th><th>De</th><th>A</th><th>Admin</th></tr></thead>
      <tbody>
        ${log.map(r => `
          <tr>
            <td>${new Date(r.at).toLocaleString()}</td>
            <td>${r.user_name}</td>
            <td>${r.from_status||'-'}</td>
            <td>${r.to_status}</td>
            <td>${r.admin_email}</td>
          </tr>
        `).join("")}
      </tbody>
    </table>
  </div>

  <div class="card">
    <h3>Cambiar clave de administrador</h3>
    <form method="POST" action="/admin/password">
      <input type="hidden" name="_csrf" value="${req.csrfToken()}">
      <div class="row">
        <input type="password" name="current" placeholder="Clave actual" required>
        <input type="password" name="next" placeholder="Nueva clave" required>
      </div>
      <button class="btn">Actualizar</button>
    </form>
  </div>
  `, { admin: req.session.admin }));
});

app.post("/admin/users/create", requireAdmin, async (req, res) => {
  const { name, email, project, code } = req.body;
  try {
    const hash = await bcrypt.hash(code, 10);
    db.prepare("INSERT INTO users (id,name,email,project,status,access_code_hash) VALUES (?,?,?,?,?,?)")
      .run(nanoid(), name.trim(), email.trim().toLowerCase(), project?.trim()||"", "NO INICIADA", hash);
    res.redirect("/admin");
  } catch (e) {
    res.send(layout("Error", `<div class="card">No se pudo crear: ${e.message} <a href="/admin">Volver</a></div>`));
  }
});

app.post("/admin/users/update", requireAdmin, (req, res) => {
  const { id, status, project } = req.body;
  const u = db.prepare("SELECT status FROM users WHERE id=?").get(id);
  if (!u) return res.send(layout("Error", `<div class="card">Usuario no existe. <a href="/admin">Volver</a></div>`));
  const upd = db.prepare("UPDATE users SET status=?, project=? WHERE id=?").run(status, project?.trim()||"", id);
  if (upd.changes) {
    db.prepare("INSERT INTO audit_log (id,user_id,admin_email,from_status,to_status) VALUES (?,?,?,?,?)")
      .run(nanoid(), id, req.session.admin, u.status, status);
  }
  res.redirect("/admin");
});

app.post("/admin/password", requireAdmin, async (req, res) => {
  const { current, next } = req.body;
  const a = db.prepare("SELECT * FROM admins WHERE email=?").get(req.session.admin);
  const ok = await bcrypt.compare(current, a.password_hash);
  if (!ok) return res.send(layout("Error", `<div class="card">Clave actual incorrecta. <a href="/admin">Volver</a></div>`));
  const hash = await bcrypt.hash(next, 10);
  db.prepare("UPDATE admins SET password_hash=? WHERE email=?").run(hash, a.email);
  res.redirect("/admin");
});

// ---------- 404 handler ----------
app.use((req, res) => {
  res.status(404).send(layout("No encontrado", `
    <div class="card">
      <h3>404 — Página no encontrada</h3>
      <p class="muted">¿Querías cerrar sesión? Usa <a href="/signout">este enlace</a>.</p>
      <p><a class="btn" href="/">Ir al inicio</a></p>
    </div>
  `));
});

// ---------- Start ----------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`> Running at http://localhost:${PORT}`));
