//
// Portal Pagos — versión con formulario vertical de alta y CRUD (editar/borrar usuarios)
// Stack: Node.js + Express + better-sqlite3 + bcrypt + helmet + csurf + better-sqlite3
// Incluye: logout unificado, logo, UI mejorada, fecha/hora, footer de marca.

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
function nowSV() {
  try {
    return new Date().toLocaleString("es-SV", { timeZone: "America/El_Salvador", hour12: false });
  } catch { return new Date().toLocaleString(); }
}

function layout(title, body, { admin, user } = {}) {
  const timestamp = nowSV();
  return `<!doctype html>
<html lang="es"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${title}</title>
<style>
  :root{--bg:#f6f7fb;--panel:#fff;--border:#eee;--text:#111;--muted:#666}
  *{box-sizing:border-box}
  body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;margin:0;background:var(--bg);color:var(--text)}
  header,footer{padding:12px 16px;background:#fff;border-bottom:1px solid var(--border);display:flex;align-items:center}
  header img{height:32px;margin-right:8px}
  header .right{margin-left:auto;display:flex;gap:12px;align-items:center}
  main{max-width:1100px;margin:24px auto;padding:0 16px}
  .card{background:#fff;border:1px solid var(--border);border-radius:16px;padding:20px;margin:16px 0;box-shadow:0 1px 2px rgba(0,0,0,.04)}
  input,select,button{font:inherit;padding:10px 12px;border-radius:12px;border:1px solid #ccc}
  label{display:block;font-size:12px;color:#444;margin:8px 0 4px}
  table{width:100%;border-collapse:collapse;background:#fff;border-radius:12px;overflow:hidden}
  th,td{padding:10px;border-bottom:1px solid var(--border);text-align:left;vertical-align:middle}
  .row{display:flex;gap:12px;flex-wrap:wrap}
  .col{display:flex;flex-direction:column;gap:8px}
  .grid-2{display:grid;grid-template-columns:1fr 1fr;gap:12px}
  .grid-3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px}
  .btn{display:inline-block;text-decoration:none;border:none;cursor:pointer;border-radius:12px;padding:10px 14px;font-weight:600}
  .btn.primary{background:#111;color:#fff}
  .btn.secondary{background:#fff;color:#111;border:1px solid #111}
  .btn.danger{background:#991b1b;color:#fff}
  .pill{display:inline-block;padding:4px 10px;border-radius:999px;font-weight:600;background:#eee}
  .muted{color:#666}
  .center{text-align:center}
  footer{border-top:1px solid var(--border);border-bottom:none;justify-content:center}
</style>
</head>
<body>
<header class="topbar">
  <img src="/logo.png" alt="Logo" onerror="this.style.display='none'">
  <strong>Portal Pagos</strong>
  <div class="right">
    <span class="muted">${timestamp} (America/El_Salvador)</span>
    ${admin ? `<span class="muted">Admin: ${admin}</span> <a class="btn secondary" href="/signout">Salir</a>`
            : user ? `<a class="btn secondary" href="/me">Mi estado</a> <a class="btn secondary" href="/signout">Salir</a>`
                   : `<a class="btn secondary" href="/login">Ingresar</a>`}
  </div>
</header>
<main>
${body}
</main>
<footer><small class="muted">© ${new Date().getFullYear()} — Spaceunity Films</small></footer>
</body></html>`;
}

function statusPill(s) {
  const map = {"NO INICIADA":"#fee2e2","RECIBO EMITIDO":"#fef3c7","CCF RECIBIDO":"#e5e7eb","CHEQUE LISTO":"#e5e7eb","TRANSFERENCIA REALIZADA":"#d1fae5"};
  const color = map[s] || "#e5e7eb";
  return `<span class="pill" style="background:${color}">${s}</span>`;
}

// ---------- Public ----------
app.get("/", (req, res) => {
  res.send(layout("Inicio", `
    <div class="card center">
      <img src="/logo.png" alt="Logo" style="max-height:90px;margin-bottom:16px;" onerror="this.style.display='none'">
      <h2>Seguimiento de pago</h2>
      <p>Ingresa con tu correo y código para ver tu estado.</p>
      <div class="row center" style="justify-content:center;margin-top:8px">
        <a class="btn primary" href="/login">Ingresar</a>
        <a class="btn secondary" href="/admin">Panel Admin</a>
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
      <label>Email</label>
      <input class="w100" type="email" name="email" placeholder="tu-correo@ejemplo.com" required>
      <label>Código de acceso</label>
      <input class="w100" type="password" name="code" placeholder="tu código de acceso" required>
      <div style="margin-top:12px"><button class="btn primary">Entrar</button></div>
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
app.all("/signout", (req, res) => { req.session.destroy(() => res.redirect("/")); });
app.all("/salir", (req, res) => { req.session.destroy(() => res.redirect("/")); });

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
      <label>Email</label>
      <input class="w100" type="email" name="email" placeholder="admin@local" required>
      <label>Contraseña</label>
      <input class="w100" type="password" name="password" placeholder="password" required>
      <div style="margin-top:12px"><button class="btn primary">Entrar</button></div>
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

// ---------- Admin panel + CRUD ----------
app.get("/admin", requireAdmin, (req, res) => {
  const users = db.prepare("SELECT id,name,email,project,status FROM users ORDER BY name").all();
  const log = db.prepare("SELECT u.name as user_name, l.* FROM audit_log l JOIN users u ON u.id=l.user_id ORDER BY at DESC LIMIT 20").all();

  res.send(layout("Panel Admin", `
  <div class="card">
    <h3>Crear usuario</h3>
    <form method="POST" action="/admin/users/create">
      <input type="hidden" name="_csrf" value="${req.csrfToken()}">
      <label>Nombre completo</label>
      <input name="name" placeholder="Nombre completo" required>
      <label>Email</label>
      <input type="email" name="email" placeholder="correo@ejemplo.com" required>
      <label>Proyecto</label>
      <input name="project" placeholder="Proyecto">
      <label>Código de acceso (entregar al usuario)</label>
      <input name="code" placeholder="p.ej. 1234" required>
      <div style="margin-top:12px">
        <button class="btn primary">Crear usuario</button>
      </div>
    </form>
  </div>

  <div class="card">
    <h3>Usuarios</h3>
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
              <div class="row" style="gap:6px;align-items:center">
                <form method="POST" action="/admin/users/update-status">
                  <input type="hidden" name="_csrf" value="${req.csrfToken()}">
                  <input type="hidden" name="id" value="${u.id}">
                  <select name="status">
                    ${STATUSES.map(s => `<option value="${s}" ${s===u.status?'selected':''}>${s}</option>`).join("")}
                  </select>
                  <button class="btn secondary">Guardar</button>
                </form>
                <form method="GET" action="/admin/users/${u.id}/edit">
                  <button class="btn secondary">Editar</button>
                </form>
                <form method="POST" action="/admin/users/delete" onsubmit="return confirm('¿Eliminar este usuario?');">
                  <input type="hidden" name="_csrf" value="${req.csrfToken()}">
                  <input type="hidden" name="id" value="${u.id}">
                  <button class="btn danger">Eliminar</button>
                </form>
              </div>
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
      <label>Clave actual</label>
      <input type="password" name="current" required>
      <label>Nueva clave</label>
      <input type="password" name="next" required>
      <div style="margin-top:12px"><button class="btn secondary">Actualizar</button></div>
    </form>
  </div>
  `, { admin: req.session.admin }));
});

// Form de edición de usuario (vertical)
app.get("/admin/users/:id/edit", requireAdmin, (req, res) => {
  const u = db.prepare("SELECT * FROM users WHERE id=?").get(req.params.id);
  if (!u) return res.send(layout("Error", `<div class="card">Usuario no existe. <a href="/admin">Volver</a></div>`));
  res.send(layout("Editar usuario", `
    <div class="card">
      <h3>Editar usuario</h3>
      <form method="POST" action="/admin/users/edit">
        <input type="hidden" name="_csrf" value="${req.csrfToken()}">
        <input type="hidden" name="id" value="${u.id}">
        <label>Nombre completo</label>
        <input name="name" value="${u.name}" required>
        <label>Email</label>
        <input type="email" name="email" value="${u.email}" required>
        <label>Proyecto</label>
        <input name="project" value="${u.project||''}">
        <label>Restablecer código (opcional)</label>
        <input name="code" placeholder="deja en blanco para no cambiar">
        <div class="row" style="margin-top:12px;gap:8px">
          <button class="btn primary">Guardar cambios</button>
          <a class="btn secondary" href="/admin">Cancelar</a>
        </div>
      </form>
    </div>
  `, { admin: req.session.admin }));
});

// Acciones CRUD
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

app.post("/admin/users/update-status", requireAdmin, (req, res) => {
  const { id, status } = req.body;
  const u = db.prepare("SELECT status FROM users WHERE id=?").get(id);
  if (!u) return res.send(layout("Error", `<div class="card">Usuario no existe. <a href="/admin">Volver</a></div>`));
  const upd = db.prepare("UPDATE users SET status=? WHERE id=?").run(status, id);
  if (upd.changes) {
    db.prepare("INSERT INTO audit_log (id,user_id,admin_email,from_status,to_status) VALUES (?,?,?,?,?)")
      .run(nanoid(), id, req.session.admin, u.status, status);
  }
  res.redirect("/admin");
});

app.post("/admin/users/edit", requireAdmin, async (req, res) => {
  const { id, name, email, project, code } = req.body;
  const u = db.prepare("SELECT * FROM users WHERE id=?").get(id);
  if (!u) return res.send(layout("Error", `<div class="card">Usuario no existe. <a href="/admin">Volver</a></div>`));
  try {
    let query, params;
    if (code && code.trim() !== "") {
      const hash = await bcrypt.hash(code.trim(), 10);
      query = "UPDATE users SET name=?, email=?, project=?, access_code_hash=? WHERE id=?";
      params = [name.trim(), email.trim().toLowerCase(), project?.trim()||"", hash, id];
    } else {
      query = "UPDATE users SET name=?, email=?, project=? WHERE id=?";
      params = [name.trim(), email.trim().toLowerCase(), project?.trim()||"", id];
    }
    db.prepare(query).run(...params);
    res.redirect("/admin");
  } catch (e) {
    res.send(layout("Error", `<div class="card">No se pudo actualizar: ${e.message} <a href="/admin">Volver</a></div>`));
  }
});

app.post("/admin/users/delete", requireAdmin, (req, res) => {
  const { id } = req.body;
  try {
    db.prepare("DELETE FROM users WHERE id=?").run(id);
    // Opcional: borrar logs asociados
    db.prepare("DELETE FROM audit_log WHERE user_id=?").run(id);
    res.redirect("/admin");
  } catch (e) {
    res.send(layout("Error", `<div class="card">No se pudo eliminar: ${e.message} <a href="/admin">Volver</a></div>`));
  }
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

// 404 handler
app.use((req, res) => {
  res.status(404).send(layout("No encontrado", `
    <div class="card center">
      <h3>404 — Página no encontrada</h3>
      <p class="muted">¿Querías cerrar sesión? Usa <a class="btn secondary" href="/signout">este enlace</a>.</p>
      <p><a class="btn primary" href="/">Ir al inicio</a></p>
    </div>
  `));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`> Running at http://localhost:${PORT}`));
