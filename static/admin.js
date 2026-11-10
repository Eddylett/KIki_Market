function filaMensaje(texto) {
  const tr = document.createElement("tr");
  const td = document.createElement("td");
  td.colSpan = 3;
  td.className = "vacio";
  td.textContent = texto;
  tr.append(td);
  return tr;
}

async function cargarTrabajadores() {
  const cuerpo = document.getElementById("tabla-trabajadores");
  cuerpo.replaceChildren(filaMensaje("Cargando..."));

  const { ok, status, datos } = await api("/usuarios");

  if (!ok) {
    cuerpo.replaceChildren(filaMensaje(textoError(datos, status)));
    return;
  }

  if (datos.length === 0) {
    cuerpo.replaceChildren(filaMensaje("No hay trabajadores registrados."));
    return;
  }

  
  cuerpo.replaceChildren(...datos.map((u) => {
    const tr = document.createElement("tr");
    [u.nombre, u.usuario, ROL_NOMBRE[u.rol] || u.rol].forEach((texto) => {
      const td = document.createElement("td");
      td.textContent = texto;
      tr.append(td);
    });
    return tr;
  }));
}

document.getElementById("form-registro").addEventListener("submit", async (e) => {
  e.preventDefault();

  const mensaje = document.getElementById("mensaje-registro");
  const boton = document.getElementById("btn-crear");

  mensaje.className = "mensaje info";
  mensaje.textContent = "Guardando...";
  boton.disabled = true;

  try {
    const { ok, status, datos } = await api("/usuarios/registro", {
      method: "POST",
      body: JSON.stringify({
        nombre: document.getElementById("reg-nombre").value.trim(),
        usuario: document.getElementById("reg-usuario").value.trim(),
        contrasena: document.getElementById("reg-contrasena").value,
        rol: document.getElementById("reg-rol").value,
      }),
    });

    if (ok) {
      mensaje.className = "mensaje ok";
      mensaje.textContent = "¡Usuario creado con éxito!";
      e.target.reset();
      cargarTrabajadores();
    } else {
      mensaje.className = "mensaje error";
      mensaje.textContent = textoError(datos, status);
    }
  } catch (err) {
    if (err.message !== "sesion") {
      mensaje.className = "mensaje error";
      mensaje.textContent = "Error de conexión.";
    }
  } finally {
    boton.disabled = false;
  }
});

cargarTrabajadores();
