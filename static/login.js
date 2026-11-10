document.getElementById("form-login").addEventListener("submit", async (e) => {
  e.preventDefault();

  const mensaje = document.getElementById("mensaje-login");
  const boton = document.getElementById("btn-ingresar");

  mensaje.className = "mensaje info";
  mensaje.textContent = "Validando credenciales...";
  boton.disabled = true;

  try {
    const r = await fetch("/usuarios/login", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        usuario: document.getElementById("login-usuario").value.trim(),
        contrasena: document.getElementById("login-contrasena").value,
      }),
    });

    const datos = await r.json();

    if (r.ok) {
      window.location.href = datos.redirigir;   
      return;
    }

    mensaje.className = "mensaje error";
    mensaje.textContent = textoError(datos, r.status);
    document.getElementById("login-contrasena").value = "";
  } catch (err) {
    mensaje.className = "mensaje error";
    mensaje.textContent = "Error de conexión.";
  } finally {
    boton.disabled = false;
  }
});
