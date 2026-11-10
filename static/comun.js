
const ROL_NOMBRE = {
  administrador: "Administrador",
  encargado_inventario: "Encargado de inventario",
  cajera: "Cajera",
};

function textoError(datos, status) {
  if (status === 429) return (datos && datos.detail) || "Demasiados intentos. Espera unos minutos.";
  if (datos && Array.isArray(datos.detail)) return "Revisa los datos ingresados.";
  return (datos && datos.detail) || "Ocurrió un error.";
}


async function api(ruta, opciones = {}) {
  const r = await fetch(ruta, {
    credentials: "same-origin",
    ...opciones,
    headers: { "Content-Type": "application/json", ...(opciones.headers || {}) },
  });

  if (r.status === 401) {
    window.location.href = "/";
    throw new Error("sesion");
  }

  let datos = null;
  try { datos = await r.json(); } catch (e) {  }

  return { ok: r.ok, status: r.status, datos };
}

async function cerrarSesion() {
  try {
    await fetch("/usuarios/logout", { method: "POST", credentials: "same-origin" });
  } finally {
    window.location.href = "/";
  }
}


async function iniciarPagina() {
  const { ok, datos } = await api("/usuarios/me");
  if (!ok) return null;

  document.getElementById("usuario-nombre").textContent = datos.nombre;
  document.getElementById("usuario-rol").textContent = ROL_NOMBRE[datos.rol] || datos.rol;
  document.getElementById("btn-salir").addEventListener("click", cerrarSesion);

  if (datos.rol === "administrador") {
    const nav = document.getElementById("nav-admin");
    [["Panel", "/admin"], ["Ver como bodega", "/inventario"], ["Ver como caja", "/caja"]]
      .forEach(([texto, ruta]) => {
        const a = document.createElement("a");
        a.href = ruta;
        a.textContent = texto;
        if (window.location.pathname === ruta) a.className = "activo";
        nav.append(a);
      });
    nav.classList.remove("oculto");
  }

  return datos;
}

if (document.body.dataset.protegida) {
  iniciarPagina();
}
