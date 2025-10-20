import json
import sqlite3
from flask import Flask, jsonify, request
import os
import copy
import uuid
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# --- Database Configuration ---
# Use an environment variable for the DB path to support persistent disks on hosts like Render.
DATABASE_FILE = os.getenv('DATABASE_PATH', 'users.db')

def init_db():
    """Initializes the database and creates the users table if it doesn't exist."""
    print(f"Initializing database at {DATABASE_FILE}...")
    try:
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        # Create table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY NOT NULL,
                password_hash TEXT NOT NULL
            );
        ''')
        conn.commit()
        conn.close()
        print("Database initialized successfully.")
    except Exception as e:
        print(f"Error initializing database: {e}")

# --- In-Memory Data Store ---
INITIAL_STATE = {}
USER_SESSIONS = {} # This will store data per user token

def load_initial_data():
    """Loads data from JSON files into the initial state template on startup."""
    global INITIAL_STATE
    print("Loading initial data from JSON files...")
    file_map = {
        'tenant': 'tenant.json',
        'cloud': 'cloud.json',
        'virtualservice': 'virtualservice.json',
        'serviceengine': 'serviceengine.json',
        'virtualservice-2ccaddb9-a3be-458e-9ad5-c0be41ce28e3': 'backend-vs-t1r_1000-1.json'
    }
    for key, filename in file_map.items():
        if os.path.exists(filename):
            with open(filename, 'r') as f:
                INITIAL_STATE[key] = json.load(f)
        else:
            print(f"Warning: Data file '{filename}' not found.")
            INITIAL_STATE[key] = {}
    print("Initial data loaded and ready.")

# --- Authentication ---

@app.route('/register', methods=['POST'])
def register():
    """Registers a new user in the SQLite database."""
    data = request.get_json()
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({"message": "Username and password are required in the JSON body"}), 400

    username = data['username']
    password = data['password']
    
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()

    cursor.execute("SELECT username FROM users WHERE username = ?", (username,))
    if cursor.fetchone():
        conn.close()
        return jsonify({"message": "User already exists. Please login."}), 409

    hashed_password = generate_password_hash(password)
    cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, hashed_password))
    
    conn.commit()
    conn.close()
    
    print(f"New user registered: '{username}'")
    return jsonify({"message": f"User '{username}' registered successfully. You can now login."}), 201


def token_required(f):
    """Decorator to protect routes with token authentication."""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            try:
                token = request.headers['Authorization'].split(" ")[1]
            except IndexError:
                return jsonify({"message": "Token is malformed!"}), 401
        
        if not token:
            return jsonify({"message": "Token is missing!"}), 401

        if token not in USER_SESSIONS:
            return jsonify({"message": "Token is invalid or session has expired!"}), 401
        
        user_data = USER_SESSIONS[token]
        return f(user_data, *args, **kwargs)
    return decorated

@app.route('/login', methods=['POST'])
def login():
    """Authenticates a user against the DB and provides a session token."""
    auth = request.authorization
    if not auth or not auth.username or not auth.password:
        return jsonify({"message": "Could not verify"}), 401, {'WWW-Authenticate': 'Basic realm="Login required!"'}

    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT password_hash FROM users WHERE username = ?", (auth.username,))
    user_record = cursor.fetchone()
    conn.close()

    if not user_record or not check_password_hash(user_record[0], auth.password):
        return jsonify({"message": "Invalid username or password"}), 401

    token = str(uuid.uuid4())
    USER_SESSIONS[token] = copy.deepcopy(INITIAL_STATE)
    print(f"User '{auth.username}' logged in. Token: {token}")
    return jsonify({"token": token})

# --- API Endpoints (No changes needed below this line) ---

@app.route('/api/tenant', methods=['GET'])
@token_required
def get_tenants(user_data):
    return jsonify(user_data.get('tenant', {}))

@app.route('/api/cloud', methods=['GET'])
@token_required
def get_clouds(user_data):
    return jsonify(user_data.get('cloud', {}))

@app.route('/api/virtualservice', methods=['GET'])
@token_required
def get_virtualservices(user_data):
    return jsonify(user_data.get('virtualservice', {}))

@app.route('/api/serviceengine', methods=['GET'])
@token_required
def get_serviceengines(user_data):
    return jsonify(user_data.get('serviceengine', {}))

@app.route('/api/virtualservice/<string:uuid>', methods=['GET', 'PUT'])
@token_required
def get_or_update_virtualservice_by_uuid(user_data, uuid):
    vs_data = None
    if uuid == 'virtualservice-2ccaddb9-a3be-458e-9ad5-c0be41ce28e3':
        vs_data = user_data.get(uuid)
    else:
        for vs in user_data.get('virtualservice', {}).get('results', []):
            if vs['uuid'] == uuid:
                vs_data = vs
                break
    
    if not vs_data:
        return jsonify({"error": "Virtual Service not found"}), 404

    if request.method == 'GET':
        return jsonify(vs_data)
        
    elif request.method == 'PUT':
        update_data = request.get_json()
        if 'enabled' in update_data:
            token = request.headers['Authorization'].split(" ")[1]
            print(f"Token {token[:8]}... updating VS {uuid}: Setting 'enabled' to {update_data['enabled']}")
            vs_data['enabled'] = update_data['enabled']
        return jsonify(vs_data)


if __name__ == '__main__':
    init_db()
    load_initial_data()
    app.run(debug=True, port=5000)

