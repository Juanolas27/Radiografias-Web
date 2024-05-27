from flask import Flask, request, render_template, make_response, redirect, url_for, jsonify
import jwt
import mysql.connector
import tensorflow as tf
import numpy as np
import cv2
import os
from functools import wraps
from cryptography.fernet import Fernet
import sendgrid
from sendgrid.helpers.mail import Mail
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from flask_cors import CORS
from dotenv import load_dotenv
import requests


load_dotenv()
app = Flask(__name__)
CORS(app)
secret_key = 'claveSecreta'
config = {
  'user': os.getenv("user"),
  'password': os.getenv("password"),
  'host': os.getenv("host"),
  'database': os.getenv("database"),
  'raise_on_warnings': True
}
serializer = URLSafeTimedSerializer(secret_key)
size = (200,200)
ruta_imagenes = "./static/imagenes_usuarios_huesos"
salt = os.getenv("salt")
model = tf.keras.models.load_model('./modelo_huesos/modelo.h5')
model.compile(optimizer = "adam", loss = "sparse_categorical_crossentropy", metrics=["accuracy"])
url_image = os.getenv("url_image")
api_key_image = os.getenv("api_key_image")
opciones = ["Fracturado", "No fracturado"]

def verificar_cookies(func):
    @wraps(func)
    def verificador(*args, **kwargs):
        # Obtener las cookies de la solicitud
        cookies = request.cookies

        token_usuario = request.cookies.get("token")
        print(token_usuario)
        if token_usuario:
            usuario = jwt.decode(token_usuario, secret_key, algorithms=["HS256"])
            print(usuario)

            with mysql.connector.connect(**config) as conexion:
                # Ejecutar operaciones en la base de datos
                cursor = conexion.cursor()

                try:
                    query = "select * from users where email = %s and contrasena = %s"
                    data = (usuario["email"], usuario["password"])
                    cursor.execute(query, data)
                    resultado = cursor.fetchall()
                    print(resultado)

                    if resultado[0][1] == usuario["email"] and resultado[0][2] == usuario["password"]:
                        print("Credenciales verificadas correctamente")
                        return func(*args, **kwargs)  # Devolver la función original

                    else:
                        response = make_response(redirect(url_for("login")))
                        return response

                except:
                    response = make_response(redirect(url_for("login")))
                    return response
        else:
            response = make_response(redirect(url_for("login")))
            return response
    return verificador



@app.route('/')
def inicio():
    return render_template("inicio.html")


@app.route("/forgot")
def forgot():
    return render_template("forgot.html")


@app.route('/ia')
@verificar_cookies
def ia():
    return render_template("ia.html")

@app.route('/contacto')
def contacto():
    return render_template("contacto.html")

@app.route("/register")
def register():
    return render_template("register.html")

@app.route("/login")
def login():
    return render_template("login.html")


@app.route("/logout")
def logout():
    response = make_response(redirect(url_for("login")))
    response.set_cookie('token', "", max_age=1, httponly=True)
    return response




@app.route("/historico")
@verificar_cookies
def historico():
    token_usuario = request.cookies.get("token")
    usuario = jwt.decode(token_usuario, secret_key, algorithms=["HS256"])
    with mysql.connector.connect(**config) as conexion:
        # Ejecutar operaciones en la base de datos
        cursor = conexion.cursor()

        try:
            query = "select * from consultas where id_usuario = %s"
            data = (usuario["id"],)
            cursor.execute(query,data)
            resultados = cursor.fetchall()

            return render_template("historico.html", data = resultados)
        except Exception as e:
            print("error: " + e)
            return "Error al procesar"


@app.route("/remake")
def recuperar_contrasena():
    token = request.args.get("token")
    if not token:
        return "Token no proporcionado", 400

    try:
        # Verificar el token y su tiempo de caducidad (en segundos, por ejemplo, 3600 para 1 hora)
        data = serializer.loads(token, salt=salt, max_age=900)
        user_id = data['user_id']
        # Proceder con el proceso de restablecimiento de contraseña
        return render_template("recover.html", user_id = user_id)
    except SignatureExpired:
        return "El enlace de restablecimiento ha expirado.", 400
    except BadSignature:
        return "El enlace de restablecimiento no es válido.", 400
    except Exception as e:
        print(e)
        return e

@app.route('/recover', methods=['POST'])
def cambio_contrasena():
    user_id = request.form['user_id']
    password = request.form['password']
    with mysql.connector.connect(**config) as conexion:
        # Ejecutar operaciones en la base de datos
        cursor = conexion.cursor()

        try:
            key = Fernet.generate_key()
            f = Fernet(key)
            password = f.encrypt(password.encode())
            query = "UPDATE users set contrasena = %s, token = %s WHERE id = %s"
            data = (password, key, user_id)
            cursor.execute(query, data)
            conexion.commit()


            query = "select * from users where id = %s"
            data = (user_id,)
            cursor.execute(query, data)
            resultado = cursor.fetchall()

            claims = {
                "id": resultado[0][0],
                "email": resultado[0][1],
                "password": resultado[0][2]
            }

            # Crea el token JWT
            token = jwt.encode(claims, secret_key, algorithm='HS256')
            response = make_response(redirect(url_for("inicio")))
            response.set_cookie('token', token, max_age=500, httponly=True)
            return response

        except Exception as e:
            return e
    return None



@app.route('/forgot', methods=['POST'])
def procesar_forgot():
    email = request.form['email']
    with mysql.connector.connect(**config) as conexion:
        # Ejecutar operaciones en la base de datos
        cursor = conexion.cursor()

        try:
            query = "select * from users where email = %s"
            data = (email,)
            cursor.execute(query,data)
            resultados = cursor.fetchall()

            if len(resultados) > 0:
                data = {'user_id': resultados[0][0]}

                # Generar el token con un tiempo de caducidad (en segundos, por ejemplo, 3600 para 1 hora)
                token = serializer.dumps(data, salt=salt)
                print("token="+token)

                base_url = 'https://radiografias-web.onrender.com/remake'
                url = f"{base_url}?token={token}"

                sg = sendgrid.SendGridAPIClient(
                    api_key=os.getenv("api_key"))

                message = Mail(
                    from_email=os.getenv("from_email"),
                    to_emails=email,
                    subject='Recuperación de contraseña RadioBone',
                    plain_text_content=url)

                response = sg.send(message)
                print(response.status_code)
                print(response.body)
                print(response.headers)
                return render_template("forgot.html")

        except Exception as e:
            print(e)


    return "Algo ha ido mal"


@app.route('/imagen', methods=['POST'])
@verificar_cookies
def procesar_imagen():
    if 'file' not in request.files:
        return 'No se encontró ningún archivo en la solicitud.', 400

    file = request.files['file']
    print(file)

    if file.filename == '':
        return 'No se seleccionó ningún archivo.', 400


    token_usuario = request.cookies.get("token")


    usuario = jwt.decode(token_usuario, secret_key, algorithms=["HS256"])
    # Aquí puedes procesar el archivo, por ejemplo, guardarlo en el servidor

    try:
        response = requests.post(url_image, files={"source": file}, data={"key": api_key_image})
        response_data = response.json()
        # Asegúrate de manejar la respuesta adecuadamente
        if response.status_code == 200:
            print('Imagen subida con éxito!')
            direccion = response_data['image']['url']
            print('URL de la imagen:', response_data['image']['url'])
            file_bytes = np.frombuffer(file.read(requests.get(response_data['image']['url'])), np.uint8)
            img = cv2.imdecode(file_bytes, cv2.IMREAD_COLOR)

            if img is None:
                return 'No se pudo leer la imagen.', 400

            # Convertir la imagen a escala de grises
            img_gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)

            # Redimensionar la imagen
            size = (100, 100)  # Ajusta el tamaño según tus necesidades
            imagen_procesada = cv2.resize(img_gray, size) / 255.0
            imagen_procesada = imagen_procesada.reshape(-1, 200, 200, 1)
            respuesta = np.argmax(model.predict(imagen_procesada))
            with mysql.connector.connect(**config) as conexion:
                # Ejecutar operaciones en la base de datos
                cursor = conexion.cursor()

                try:
                    query = "select * from users where contrasena = %s"
                    data = (usuario["password"],)
                    cursor.execute(query, data)
                    x = cursor.fetchall()
                    query = "INSERT INTO consultas (id_usuario, img, commentary) VALUES (%s, %s, %s)"
                    data = (x[0][0], direccion, opciones[respuesta])
                    cursor.execute(query, data)
                    conexion.commit()
                    return opciones[respuesta]

                except Exception as e:

                    # En caso de error, imprimir el error y revertir la transacción

                    print(f"Error al ejecutar la consulta: {e}")

                    conexion.rollback()
            return opciones[respuesta]
        else:
            return f'Error en la solicitud externa: {response.status_code} {response.text}', response.status_code

    except Exception as e:
        print(f'Error al procesar la imagen: {str(e)}')
        return 'Error al procesar la imagen.', 500







@app.route('/register', methods=['POST'])
def procesar_formulario_register():
    # Verificar si la solicitud es POST
    if request.method == 'POST':
        # Obtener los datos del formulario
        password = request.form['password']
        email = request.form['email']
        key = Fernet.generate_key()
        f = Fernet(key)
        password = f.encrypt(password.encode())

        with mysql.connector.connect(**config) as conexion:
            # Ejecutar operaciones en la base de datos
            cursor = conexion.cursor()

            try:
                query = "INSERT INTO users (email, contrasena, token) VALUES (%s, %s, %s)"
                data = (email, password.decode(), key.decode())
                cursor.execute(query, data)
                conexion.commit()
                query = "select * from users where email = %s and contrasena = %s"
                data = (email, password)
                cursor.execute(query, data)
                resultado = cursor.fetchall()
                secret_key = 'claveSecreta'

                claims = {
                    "id": resultado[0][0],
                    "email": resultado[0][1],
                    "password": resultado[0][2]
                }


                # Crea el token JWT
                token = jwt.encode(claims, secret_key, algorithm='HS256')
                response = make_response(redirect(url_for("inicio")))
                response.set_cookie('token', token, max_age=500, httponly=True)
                return response

            except Exception as e:
                return "Este email ya está registrado\n"+e



@app.route('/login', methods=['POST'])
def procesar_formulario_login():
    # Verificar si la solicitud es POST
    if request.method == 'POST':
        # Obtener los datos del formulario
        password = request.form['password']
        email = request.form['email']

        with mysql.connector.connect(**config) as conexion:
            # Ejecutar operaciones en la base de datos
            cursor = conexion.cursor()

            try:
                query = "select * from users where email = %s"
                data = (email,)
                cursor.execute(query, data)
                resultado = cursor.fetchall()

                if len(resultado) > 0:
                    if Fernet(resultado[0][3].encode()).decrypt(resultado[0][2].encode()).decode() == password:
                        secret_key = 'claveSecreta'
                        claims = {
                            "id": resultado[0][0],
                            "email": resultado[0][1],
                            "password": resultado[0][2]
                        }

                        # Crea el token JWT
                        token = jwt.encode(claims, secret_key, algorithm='HS256')
                        response = make_response(redirect(url_for("inicio")))
                        response.set_cookie('token', token, max_age=500, httponly=False)
                        return response

                    else:
                        return "Este email con esta password no se encuentra en la base de datos"



            except Exception as e:

                print(f"Error: {e}")

                    # En caso de que no se devuelva una respuesta válida dentro del bloque try, devuelve una respuesta de error

            return make_response('Error procesando el formulario de login', 500)


if __name__ == '__main__':
    app.run(debug=True)
