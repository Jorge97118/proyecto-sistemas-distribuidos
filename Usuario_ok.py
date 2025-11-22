from flask import Flask, request, jsonify
import psycopg2
from psycopg2 import extras
import bcrypt
import os

app = Flask(__name__)

# --- CONFIGURACIÓN DE LA BASE DE DATOS ---
# Usamos las variables de entorno de Docker Compose para la conexión
DB_HOST = os.environ.get('DB_HOST', 'postgres') # 'postgres' si corre en Docker, 'localhost' si corre fuera
DB_NAME = os.environ.get('POSTGRES_DB', 'chatdb')
DB_USER = os.environ.get('POSTGRES_USER', 'appuser')
DB_PASSWORD = os.environ.get('POSTGRES_PASSWORD', 'secretpassword')

def get_db_connection():
    """Establece y retorna una conexión a la base de datos PostgreSQL."""
    try:
        conn = psycopg2.connect(
            host=DB_HOST,
            database=DB_NAME,
            user=DB_USER,
            password=DB_PASSWORD
        )
        return conn
    except psycopg2.OperationalError as e:
        # En el entorno de Docker, el contenedor puede tardar en arrancar.
        # Si la conexión falla, imprimimos el error en el log de Flask.
        print(f"ERROR: No se pudo conectar a la base de datos. Detalles: {e}")
        return None

# --- RUTAS DE LA APLICACIÓN ---

@app.route('/')
def home():
    """Ruta inicial para verificar que el servidor Flask esté activo."""
    return "Servidor Flask funcionando. Listo para el Registro."

@app.route('/register', methods=['POST'])
def register_user():
    """Ruta para registrar un nuevo usuario en la base de datos."""
    conn = get_db_connection()
    if conn is None:
        return jsonify({"message": "Error interno del servidor: Falló la conexión a la base de datos."}), 500

    # 1. Recibir los datos del formulario
    data = request.get_json(silent=True)
    if data is None:
        data = request.form # Intenta obtener datos de formulario estándar

    username = data.get('username')
    email = data.get('email')
    password = data.get('password') 

    # 2. Verificar datos obligatorios
    if not username or not email or not password:
        conn.close()
        return jsonify({"message": "Faltan datos de usuario, correo o contraseña"}), 400

    # 3. Encriptar la contraseña (¡IMPORTANTE por seguridad!)
    # Genera un 'salt' (valor aleatorio) y luego hashea la contraseña
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    cursor = conn.cursor()
    
    try:
        # 4. Construir la consulta SQL para insertar
        # CORRECCIÓN: Usamos la tabla 'users' y añadimos RETURNING id
        query = """
        INSERT INTO users (username, email, password_hash) 
        VALUES (%s, %s, %s) RETURNING id;
        """
        # Ejecutar la consulta con los valores seguros
        cursor.execute(query, (username, email, hashed_password))
        
        # OBTENER EL ID ÚNICO GENERADO
        user_id = cursor.fetchone()[0]
        
        # Confirmar la transacción para guardar los cambios en la DB
        conn.commit()
        
        # Registro exitoso
        return jsonify({
            "message": "Usuario registrado exitosamente en la base de datos.",
            "user_id": user_id, # INCLUIMOS EL ID EN LA RESPUESTA
            "usuario": username,
            "correo": email
        }), 201

    except psycopg2.IntegrityError:
        # Esto ocurre si el email o username ya existen (por la restricción UNIQUE)
        conn.rollback() # Deshace cualquier cambio
        return jsonify({"message": "Error: El usuario o correo electrónico ya está registrado."}), 409

    except Exception as e:
        # Cualquier otro error
        conn.rollback()
        print(f"Error al registrar usuario: {e}")
        return jsonify({"message": "Error interno al procesar el registro.", "error_detail": str(e)}), 500
        
    finally:
        # Asegurarse de cerrar el cursor y la conexión
        cursor.close()
        conn.close()


if __name__ == '__main__':
    app.run(debug=True)
