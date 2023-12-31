import base64
import hashlib
import random
import string
import threading
from urllib.parse import urlencode
import webbrowser

import sqlalchemy
import pandas as pd
import requests
from datetime import datetime, timedelta
import sqlite3

from flask import Flask, request


DATABASE_LOCATION = "sqlite:///my_played_tracks.sqlite"
CLIENT_ID = '#YOUR_CLIENTE_ID'
REDIRECT_URI = 'http://localhost:3000'
ACCESS_TOKEN_FILE = 'access_token.txt'
CODE_VERIFIER_FILE = 'code_verifier.txt'


app = Flask(__name__)

@app.route('/')
def handle_redirect():
    # Capturar los parámetros de la URL
    code = request.args.get('code')
    state = request.args.get('state')

    # Aquí puedes procesar los datos como lo necesites
    print(f'Código: {code}, Estado: {state}')
    code_verifier = read_file(CODE_VERIFIER_FILE)

    if code_verifier and code:
        token = get_token(code_verifier, code)
        if token:
            song_df = extract_data(token)
                
            # Validate
            if check_if_valid_data(song_df):
                print("Datos válidos!")
                
                load_data(song_df)

    return 'Redirección completada. Puedes cerrar esta ventana.'


def read_file(file):
    try:
        with open(file, 'r') as file:
            data = file.read().strip()
            return data
    except Exception:
        return None

def generate_code() -> tuple[str, str]:
    rand = random.SystemRandom()
    code_verifier = ''.join(rand.choices(string.ascii_letters + string.digits, k=128))

    code_sha_256 = hashlib.sha256(code_verifier.encode('utf-8')).digest()
    b64 = base64.urlsafe_b64encode(code_sha_256)
    code_challenge = b64.decode('utf-8').replace('=', '')

    return (code_verifier, code_challenge)

def authorize():
    code_verifier, code_challenge = generate_code()
    scope = 'user-read-recently-played'
    auth_url = 'https://accounts.spotify.com/authorize'
    code_challenge_method = 'S256'

    # Set code_verifier in localStorage (equivalent to localStorage.setItem in JavaScript)
    # Note: In Python, you might use a file or a database to persist this value across sessions
    with open(CODE_VERIFIER_FILE, 'w') as file:
        file.write(code_verifier)

    # Construct the authorization URL
    params = {
        'response_type': 'code',
        'client_id': CLIENT_ID,
        'scope': scope,
        'code_challenge_method': code_challenge_method,
        'code_challenge': code_challenge,
        'redirect_uri': REDIRECT_URI,
    }

    auth_url_with_params = f"{auth_url}?{urlencode(params)}"

    webbrowser.open(auth_url_with_params)


def get_token(code_verifier, code):
    code_verifier = code_verifier
    token_url = 'https://accounts.spotify.com/api/token'

    payload = {
        'client_id': CLIENT_ID,
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': REDIRECT_URI,
        'code_verifier': code_verifier,
    }

    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
    }

    response = requests.post(token_url, data=payload, headers=headers)

    if response.status_code == 200:
        data = response.json()
        access_token = data.get('access_token')
        if access_token:
            # Almacenar el token de acceso
            with open(ACCESS_TOKEN_FILE, 'w') as file:
                file.write(access_token)
            print('Token de acceso almacenado con éxito.')
            return access_token
        else:
            print('Error al obtener el token de acceso.')
            return None
    else:
        print(f'Error: {response.status_code}')
        print(response.text)
        return None

def extract_data(token: str):
    # Extract part of the ETL process

    headers = {
        "Accept" : "application/json",
        "Content-Type" : "application/json",
        "Authorization" : "Bearer {token}".format(token=token)
    }

    # Convert time to Unix timestamp in miliseconds      
    today = datetime.now()
    yesterday = today - timedelta(days=30)
    yesterday_unix_timestamp = int(yesterday.timestamp()) * 1000

    # Download all songs you've listened to "after yesterday", which means in the last 24 hours      
    r = requests.get(f"https://api.spotify.com/v1/me/player/recently-played?after={yesterday_unix_timestamp}&limit=50", headers = headers)

    if r.status_code == 200:
        data = r.json()

        # print(data['items'])

        song_names = []
        artist_names = []
        played_at_list = []
        timestamps = []

        # Extracting only the relevant bits of data from the json object      
        for song in data["items"]:
            song_names.append(song["track"]["name"])
            artist_names.append(song["track"]["album"]["artists"][0]["name"])
            played_at_list.append(song["played_at"])
            timestamps.append(song["played_at"][0:10])
            
        # Prepare a dictionary in order to turn it into a pandas dataframe below       
        song_dict = {
            "song_name" : song_names,
            "artist_name": artist_names,
            "played_at" : played_at_list,
            "timestamp" : timestamps
        }

        song_df = pd.DataFrame(song_dict, columns = ["song_name", "artist_name", "played_at", "timestamp"])
        # print(song_df)
        return song_df
    else:
        with open(ACCESS_TOKEN_FILE, 'w') as file:
            file.write('')
        try:
            response = r.json()
            print('API error:', response['error']['message'])
        except Exception:
            print('Server error: Vuelva a correr el codigo.')
        raise Exception("Server error: Vuelva a correr el codigo.")

def check_if_valid_data(df: pd.DataFrame) -> bool:
    # Check if dataframe is empty
    if df.empty:
        print("No se descargaron canciones. Finalizando la ejecución!")
        return False 

    # Primary Key Check
    if pd.Series(df['played_at']).is_unique:
        pass
    else:
        raise Exception("Se ha violado la verificación de clave principal")

    # Check for nulls
    if df.isnull().values.any():
        raise Exception("Valores nulos encontrados")

    # Fecha de hoy
    today = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)

    # Calcular la fecha de hace 30 días
    thirty_days_ago = today - timedelta(days=30)

    # Obtener las marcas de tiempo del DataFrame
    timestamps = df["timestamp"].tolist()

    # Verificar si al menos una marca de tiempo está en el rango de los últimos 30 días
    for timestamp in timestamps:
        if datetime.strptime(timestamp, '%Y-%m-%d') < thirty_days_ago:
            raise Exception("Al menos una de las canciones devueltas no pertenece a los últimos 30 días..")

    return True

def load_data(song_df: pd.DataFrame):
    engine = sqlalchemy.create_engine(DATABASE_LOCATION)
    conn = sqlite3.connect('my_played_tracks.sqlite')
    cursor = conn.cursor()

    sql_query = """
    CREATE TABLE IF NOT EXISTS my_played_tracks(
        song_name VARCHAR(200),
        artist_name VARCHAR(200),
        played_at VARCHAR(200),
        timestamp VARCHAR(200),
        CONSTRAINT primary_key_constraint PRIMARY KEY (played_at)
    )
    """

    cursor.execute(sql_query)
    print("Base de datos abierta con éxito")

    try:
        song_df.to_sql("my_played_tracks", engine, index=False, if_exists='append')
        print('Datos agregados exitosamente')
    except Exception:
        print("Los datos ya existen en la base de datos.")

    conn.close()
    print("Cerrar base de datos exitosamente")


def run_flask():
    # Iniciar el servidor en un hilo separado
    app.run(port=3000)


if __name__ == "__main__":
    access_token = read_file(ACCESS_TOKEN_FILE)
    if access_token:
        song_df = extract_data(access_token)  
        # Validate
        if check_if_valid_data(song_df):
            print("Datos válidos!")
            
            load_data(song_df)
    else:
        # Iniciar Flask en un hilo separado
        flask_thread = threading.Thread(target=run_flask)
        flask_thread.start()

        authorize()

        flask_thread.join()
