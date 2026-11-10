import os
import json
import hmac
import hashlib
import base64
import time
from pathlib import Path

import psycopg2

from fastapi import FastAPI, HTTPException, Depends, Request, Response
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from passlib.context import CryptContext
from dotenv import load_dotenv

load_dotenv()

BASE = Path(__file__).parent

DATABASE_URL = os.getenv("DATABASE_URL")
TOKEN_SECRET = os.getenv("TOKEN_SECRET")
DEBUG = os.getenv("DEBUG", "false").lower() == "true"
# En produccion (HTTPS) poner COOKIE_SECURE=true en el .env
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "false").lower() == "true"

if not DATABASE_URL:
    raise RuntimeError("Falta configurar DATABASE_URL en .env")

if not TOKEN_SECRET or len(TOKEN_SECRET) < 32:
    raise RuntimeError("Configura TOKEN_SECRET con una clave segura de al menos 32 caracteres")

COOKIE_NOMBRE = "kiki_sesion"
DURACION_SESION = 3600  

# ROLES Y PAGINAS
ROLES = ("administrador", "encargado_inventario", "cajera")

INICIO_POR_ROL = {
    "administrador": "/admin",
    "encargado_inventario": "/inventario",
    "cajera": "/caja",
}

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


HASH_FALSO = pwd_context.hash("clave-falsa-para-igualar-tiempos")



app = FastAPI(
    title="Kiki Market API",
    docs_url="/docs" if DEBUG else None,
    redoc_url=None,
    openapi_url="/openapi.json" if DEBUG else None,
)

app.mount("/static", StaticFiles(directory=BASE / "static"), name="static")



@app.middleware("http")
async def cabeceras_seguridad(request: Request, call_next):
    respuesta = await call_next(request)

    respuesta.headers["X-Content-Type-Options"] = "nosniff"
    respuesta.headers["X-Frame-Options"] = "DENY"
    respuesta.headers["Referrer-Policy"] = "no-referrer"
    
    respuesta.headers["Permissions-Policy"] = "camera=(self), microphone=(), geolocation=()"

    if request.url.path not in ("/docs", "/openapi.json"):
        respuesta.headers["Content-Security-Policy"] = (
            "default-src 'self'; frame-ancestors 'none'; form-action 'self'"
        )

    if not request.url.path.startswith("/static"):
        respuesta.headers["Cache-Control"] = "no-store"

    return respuesta



def obtener_conexion():
    try:
        return psycopg2.connect(DATABASE_URL)
    except Exception:
        return None



MAX_INTENTOS = 5
VENTANA_SEGUNDOS = 300
intentos_fallidos = {}


def login_bloqueado(clave):
    ahora = time.time()
    recientes = [t for t in intentos_fallidos.get(clave, []) if ahora - t < VENTANA_SEGUNDOS]
    intentos_fallidos[clave] = recientes
    return len(recientes) >= MAX_INTENTOS


def registrar_fallo(clave):
    intentos_fallidos.setdefault(clave, []).append(time.time())


def limpiar_fallos(clave):
    intentos_fallidos.pop(clave, None)


# FUNCIONES PARA GENERAR TOKENS
def crear_token(id_usuario):
    datos = {
        "id": id_usuario,
        "exp": int(time.time()) + DURACION_SESION
    }

    contenido = json.dumps(datos).encode()
    mensaje = base64.urlsafe_b64encode(contenido).decode().rstrip("=")

    firma = hmac.new(
        TOKEN_SECRET.encode(),
        mensaje.encode(),
        hashlib.sha256
    ).digest()

    firma_codificada = base64.urlsafe_b64encode(firma).decode().rstrip("=")

    return mensaje + "." + firma_codificada


def verificar_token(token):
    try:
        mensaje, firma_recibida = token.split(".")

        firma_correcta = hmac.new(
            TOKEN_SECRET.encode(),
            mensaje.encode(),
            hashlib.sha256
        ).digest()

        firma_esperada = base64.urlsafe_b64encode(
            firma_correcta
        ).decode().rstrip("=")

        if not hmac.compare_digest(firma_recibida, firma_esperada):
            raise ValueError()

        contenido = mensaje + "=" * (-len(mensaje) % 4)

        datos = json.loads(
            base64.urlsafe_b64decode(contenido)
        )

        if datos["exp"] < int(time.time()):
            raise ValueError()

        return datos["id"]

    except Exception:
        raise HTTPException(
            status_code=401,
            detail="Sesión inválida o expirada"
        )



def obtener_usuario_actual(request: Request):
    token = request.cookies.get(COOKIE_NOMBRE)

    if not token:
        raise HTTPException(status_code=401, detail="No has iniciado sesión")

    id_usuario = verificar_token(token)

    conn = obtener_conexion()

    if not conn:
        raise HTTPException(
            status_code=500,
            detail="Error de conexión a la base de datos"
        )

    cursor = conn.cursor()

    try:
        
        cursor.execute(
            "SELECT id_usuario, nombre, usuario, rol FROM usuarios WHERE id_usuario = %s",
            (id_usuario,)
        )

        usuario = cursor.fetchone()

        if not usuario:
            raise HTTPException(status_code=401, detail="Usuario no encontrado")

        return {
            "id": usuario[0],
            "nombre": usuario[1],
            "usuario": usuario[2],
            "rol": usuario[3]
        }

    finally:
        cursor.close()
        conn.close()


def requiere_rol(*roles_permitidos):
    """Uso: Depends(requiere_rol("cajera", "administrador"))"""
    def dependencia(usuario=Depends(obtener_usuario_actual)):
        if usuario["rol"] not in roles_permitidos:
            raise HTTPException(
                status_code=403,
                detail="No tienes permisos para esta acción"
            )
        return usuario

    return dependencia


verificar_administrador = requiere_rol("administrador")



class UsuarioCrear(BaseModel):
    nombre: str = Field(min_length=2, max_length=80)
    usuario: str = Field(min_length=3, max_length=30, pattern=r"^[a-zA-Z0-9._-]+$")
    contrasena: str = Field(min_length=8, max_length=72)  # bcrypt solo usa 72 bytes
    rol: str


class UsuarioLogin(BaseModel):
    usuario: str = Field(max_length=30)
    contrasena: str = Field(max_length=72)



def servir_pagina(request: Request, archivo: str, roles_permitidos):
    try:
        usuario = obtener_usuario_actual(request)
    except HTTPException:
        return RedirectResponse("/", status_code=303)

    if usuario["rol"] not in roles_permitidos:
        destino = INICIO_POR_ROL.get(usuario["rol"])
        if not destino:
            return RedirectResponse("/", status_code=303)
        return RedirectResponse(destino, status_code=303)

    return FileResponse(BASE / "paginas" / archivo)


@app.get("/", include_in_schema=False)
def cargar_inicio(request: Request):
    try:
        usuario = obtener_usuario_actual(request)
        if usuario["rol"] in INICIO_POR_ROL:
            return RedirectResponse(INICIO_POR_ROL[usuario["rol"]], status_code=303)
    except HTTPException:
        pass

    return FileResponse(BASE / "paginas" / "index.html")


@app.get("/admin", include_in_schema=False)
def pagina_admin(request: Request):
    return servir_pagina(request, "admin.html", ("administrador",))



@app.get("/inventario", include_in_schema=False)
def pagina_inventario(request: Request):
    return servir_pagina(request, "inventario.html", ("administrador", "encargado_inventario"))


@app.get("/caja", include_in_schema=False)
def pagina_caja(request: Request):
    return servir_pagina(request, "caja.html", ("administrador", "cajera"))



@app.post("/usuarios/login")
def login_usuario(datos: UsuarioLogin, request: Request, response: Response):
    ip = request.client.host if request.client else "desconocida"
    clave = ip + "|" + datos.usuario.lower()

    if login_bloqueado(clave):
        raise HTTPException(
            status_code=429,
            detail="Demasiados intentos fallidos. Espera unos minutos e inténtalo de nuevo."
        )

    conn = obtener_conexion()

    if not conn:
        raise HTTPException(
            status_code=500,
            detail="Error de conexión a la base de datos"
        )

    cursor = conn.cursor()

    try:
        cursor.execute(
            """
            SELECT id_usuario, nombre, contraseñahash, rol
            FROM usuarios
            WHERE usuario = %s;
            """,
            (datos.usuario,)
        )
        usuario_db = cursor.fetchone()

        hash_guardado = usuario_db[2] if usuario_db else HASH_FALSO
        clave_valida = pwd_context.verify(datos.contrasena, hash_guardado)

        if not usuario_db or not clave_valida:
            registrar_fallo(clave)
            raise HTTPException(
                status_code=401,
                detail="Usuario o contraseña incorrectos"
            )

        limpiar_fallos(clave)

        id_usuario, nombre, _, rol = usuario_db
        token = crear_token(id_usuario)

        
        response.set_cookie(
            key=COOKIE_NOMBRE,
            value=token,
            max_age=DURACION_SESION,
            httponly=True,
            samesite="strict",
            secure=COOKIE_SECURE,
            path="/",
        )

        return {
            "mensaje": "Ingreso exitoso a Kiki Market",
            "nombre": nombre,
            "rol": rol,
            "redirigir": INICIO_POR_ROL.get(rol, "/")
        }

    finally:
        cursor.close()
        conn.close()



@app.post("/usuarios/logout")
def logout_usuario(response: Response):
    response.delete_cookie(COOKIE_NOMBRE, path="/")
    return {"mensaje": "Sesión cerrada"}



@app.post("/usuarios/registro")
def registrar_usuario(
    datos: UsuarioCrear,
    administrador=Depends(verificar_administrador)
):
    if datos.rol not in ("encargado_inventario", "cajera"):
        raise HTTPException(
            status_code=400,
            detail="Rol no permitido"
        )

    conn = obtener_conexion()

    if not conn:
        raise HTTPException(
            status_code=500,
            detail="Error de conexión a la base de datos"
        )

    cursor = conn.cursor()

    try:
        contrasena_hash = pwd_context.hash(datos.contrasena)

        cursor.execute(
            """
            INSERT INTO usuarios (nombre, usuario, contraseñahash, rol)
            VALUES (%s, %s, %s, %s)
            RETURNING id_usuario;
            """,
            (datos.nombre.strip(), datos.usuario, contrasena_hash, datos.rol)
        )

        nuevo_id = cursor.fetchone()[0]
        conn.commit()

        return {
            "mensaje": "Usuario creado con éxito",
            "id_usuario": nuevo_id,
            "usuario": datos.usuario
        }

    except psycopg2.IntegrityError:
        conn.rollback()
        raise HTTPException(
            status_code=400,
            detail="El nombre de usuario ya existe"
        )

    except Exception:
        conn.rollback()
        raise HTTPException(
            status_code=500,
            detail="No se pudo crear el usuario"
        )

    finally:
        cursor.close()
        conn.close()


# LISTAR TRABAJADORES
@app.get("/usuarios")
def listar_usuarios(administrador=Depends(verificar_administrador)):
    conn = obtener_conexion()

    if not conn:
        raise HTTPException(
            status_code=500,
            detail="Error de conexión a la base de datos"
        )

    cursor = conn.cursor()

    try:
        cursor.execute("""
            SELECT id_usuario, nombre, usuario, rol
            FROM usuarios
            WHERE rol != 'administrador'
            ORDER BY nombre;
        """)

        return [
            {"id": f[0], "nombre": f[1], "usuario": f[2], "rol": f[3]}
            for f in cursor.fetchall()
        ]

    finally:
        cursor.close()
        conn.close()


@app.get("/usuarios/me")
def consultar_sesion(usuario=Depends(obtener_usuario_actual)):
    return {**usuario, "inicio": INICIO_POR_ROL.get(usuario["rol"], "/")}
