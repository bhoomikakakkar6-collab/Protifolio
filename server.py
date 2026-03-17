from flask import Flask, request, jsonify
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import psycopg2
import psycopg2.extras

app = Flask(__name__)
CORS(app)

# ── Database Config ──────────────────────────────────────
DB_CONFIG = {
    "host":     "localhost",
    "dbname":   "postgres",
    "user":     "postgres",
    "password": "kakkar3010",
    "port":     5432
}

# ── Get Database Connection ──────────────────────────────
def get_db_connection():
    conn = psycopg2.connect(**DB_CONFIG)
    conn.cursor_factory = psycopg2.extras.DictCursor
    return conn

# ── Create Table ─────────────────────────────────────────
def create_table():
    conn = None
    cur  = None
    try:
        conn = get_db_connection()
        cur  = conn.cursor()
        create_script = """
            CREATE TABLE IF NOT EXISTS server (
                id       SERIAL PRIMARY KEY,
                username VARCHAR(255) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL
            )
        """
        cur.execute(create_script)
        conn.commit()
        print("Table 'server' is ready!")

    except Exception as error:
        print("Error creating table:", error)

    finally:
        if cur  is not None: cur.close()
        if conn is not None: conn.close()

# ── Register Route ───────────────────────────────────────
@app.route('/register', methods=['POST'])
def register():
    data     = request.get_json()
    email    = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400

    if '@' not in email or '.' not in email.split('@')[-1]:
        return jsonify({"error": "Invalid email format"}), 400
     # ── Check password strength ───────────────────────────
    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400

    if not any(char.isdigit() for char in password):
        return jsonify({"error": "Password must contain at least one number"}), 400
    
    if not any(char.isupper() for char in password):
        return jsonify({"error": "Password must contain at least one uppercase letter"}), 400
   
    if not any(char.islower() for char in password):
        return jsonify({"error": "Password must contain at least one lowercase letter"}), 400


    conn = None
    cur  = None
    try:
        conn = get_db_connection()
        cur  = conn.cursor()

        # Check if email already exists
        cur.execute("SELECT 1 FROM server WHERE username = %s", (email,))
        if cur.fetchone():
            return jsonify({"error": "This email is already registered."}), 409

        hashed_password = generate_password_hash(password)
        cur.execute(
            "INSERT INTO server (username, password) VALUES (%s, %s)",
            (email, hashed_password)
        )
        conn.commit()
        return jsonify({"message": "User registered successfully!"}), 201

    except Exception as error:
        print("Register error:", error)
        return jsonify({"error": "Registration failed."}), 500

    finally:
        if cur  is not None: cur.close()
        if conn is not None: conn.close()

@app.route('/login', methods=['POST'])
def login():
    data     = request.get_json()
    email    = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400

    conn = None
    cur  = None
    try:
        conn = get_db_connection()
        cur  = conn.cursor()
        cur.execute("SELECT * FROM server WHERE username = %s", (email,))
        user = cur.fetchone()

        if user and check_password_hash(user['password'], password):
            ip_address = request.remote_addr

            # ── Count only THIS user's logins ─────────────
            cur.execute(
                "SELECT COUNT(*) FROM login_history WHERE email = %s",
                (email,)   # ← only counts rows where email matches
            )
            count = cur.fetchone()[0]

            # ── Insert new login record ───────────────────
            cur.execute(
                "INSERT INTO login_history (email, ip_address, login_count) VALUES (%s, %s, %s)",
                (email, ip_address, count + 1)
            )
            conn.commit()
            return jsonify({
                "message": "Login successful!",
                "login_count": count + 1   # ← shows count in response
            }), 200
        else:
            return jsonify({"error": "Invalid email or password"}), 401

    except Exception as error:
        print("Login error:", error)
        return jsonify({"error": "Login failed."}), 500

    finally:
        if cur  is not None: cur.close()
        if conn is not None: conn.close()
@app.route('/delete_user', methods=['DELETE'])
def delete_user():
    data  = request.get_json()
    email = data.get('email')

    if not email:
        return jsonify({"error": "Email is required"}), 400

    conn = None
    cur  = None
    try:
        conn = get_db_connection()
        cur  = conn.cursor()
        cur.execute("DELETE FROM server WHERE username = %s", (email,))
        conn.commit()
        return jsonify({"message": "User deleted!"}), 200

    except Exception as error:
        print("Delete error:", error)
        return jsonify({"error": "Delete failed"}), 500

    finally:
        if cur  is not None: cur.close()
        if conn is not None: conn.close()

# ── Create Login History Table ───────────────────────────
def create_login_history_table():
    conn = None
    cur  = None
    try:
        conn = get_db_connection()
        cur  = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS login_history (
                id         SERIAL PRIMARY KEY,
                email      VARCHAR(255) NOT NULL,
                login_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                ip_address VARCHAR(50)
            )
        """)
        conn.commit()
        print("Table 'login_history' is ready!")
    except Exception as error:
        print("Error:", error)
    finally:
        if cur  is not None: cur.close()
        if conn is not None: conn.close()
@app.route('/login_history', methods=['GET'])
def login_counter():
    conn = None
    cur  = None
    try:
        conn = get_db_connection()
        cur  = conn.cursor()
        cur.execute("""
            SELECT email, COUNT(*) as total_logins
            FROM login_history
            GROUP BY email
            ORDER BY total_logins DESC
        """)
        rows   = cur.fetchall()
        result = [{"email": row['email'], "total_logins": row['total_logins']} for row in rows]
        return jsonify(result), 200

    except Exception as error:
        print("Error:", error)
        return jsonify({"error": "Failed to fetch login count"}), 500

    finally:
        if cur  is not None: cur.close()
        if conn is not None: conn.close()

if __name__ == '__main__':
    print("Connecting to database...")
    create_table()
    create_login_history_table()
    print("Server starting at http://localhost:5000")
    app.run(debug=True, port=5000)