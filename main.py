import os
import psycopg2
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from passlib.context import CryptContext
from dotenv import load_dotenv

# Cargar las variables secretas del archivo .env
load_dotenv()
DATABASE_URL = os.getenv("DATABASE_URL")

# Configurar el sistema de encriptación de contraseñas (bcrypt)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

app = FastAPI(title="Kiki Market API")

# Función para conectarse a PostgreSQL
def obtener_conexion():
    try:
        conn = psycopg2.connect(DATABASE_URL)
        return conn
    except Exception as e:
        print(f"Error conectando a la base de datos: {e}")
        return None

# Estructura que debe enviar el usuario al registrarse
class UsuarioCrear(BaseModel):
    nombre: str
    usuario: str
    contrasena: str
    rol: str

@app.get("/")
def ruta_inicio():
    return {"mensaje": "Bienvenido a la API de Kiki Market"}

# Endpoint para registrar un usuario guardando la contraseña ENCRIPTADA
@app.post("/usuarios/registro")
def registrar_usuario(datos: UsuarioCrear):
    conn = obtener_conexion()
    if not conn:
        raise HTTPException(status_code=500, detail="Error de conexión a la Base de Datos")
    
    cursor = conn.cursor()
    
    # 1. Encriptar la contraseña antes de guardar
    contrasena_hash = pwd_context.hash(datos.contrasena)
    
    try:
        # 2. Insertar en la tabla creada en Supabase
        query = """
            INSERT INTO usuarios (nombre, usuario, contraseñahash, rol)
            VALUES (%s, %s, %s, %s)
            RETURNING id_usuario;
        """
        cursor.execute(query, (datos.nombre, datos.usuario, contrasena_hash, datos.rol))
        nuevo_id = cursor.fetchone()[0]
        conn.commit()
        
        cursor.close()
        conn.close()
        
        return {
            "mensaje": "Usuario creado con éxito",
            "id_usuario": nuevo_id,
            "usuario": datos.usuario
        }
    except Exception as e:
        conn.rollback()
        cursor.close()
        conn.close()
        raise HTTPException(status_code=400, detail=f"No se pudo crear el usuario: {str(e)}")