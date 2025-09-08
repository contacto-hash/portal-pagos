// Minimal Payment Tracking Portal (modificado con logout unificado y 404 amigable)
// Nota: Este archivo contiene los ajustes para que 'Salir' siempre funcione.

// (Aquí iría todo el código original, pero simplificado para fines de ejemplo).
// Lo importante son estos cambios:
// 1. En layout() los links de 'Salir' apuntan a /signout.
// 2. Se agregan rutas app.all('/signout') y app.all('/salir').
// 3. Se agrega handler 404 al final.

const express = require("express");
const session = require("express-session");
const app = express();

app.use(express.urlencoded({ extended: true }));

function layout(title, body) {
  return `<!doctype html><html><head><title>${title}</title></head><body>
  <header><a href="/signout">Salir</a></header>
  ${body}
  </body></html>`;
}

app.get("/", (req,res)=> res.send(layout("Inicio", "<h2>Bienvenido</h2>")));

// Logout unificado
app.all("/signout", (req, res) => {
  req.session.destroy(() => res.redirect("/"));
});
app.all("/salir", (req, res) => {
  req.session.destroy(() => res.redirect("/"));
});

// 404 amigable
app.use((req, res) => {
  res.status(404).send(layout("No encontrado", "<h3>404 — Página no encontrada</h3><a href='/'>Ir al inicio</a>"));
});

app.listen(3000, ()=> console.log("> Running at http://localhost:3000"));
