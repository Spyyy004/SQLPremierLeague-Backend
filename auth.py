from flask import Flask, request, jsonify, make_response
from flask_bcrypt import Bcrypt
from flask_jwt_extended import create_access_token, jwt_required, create_refresh_token, JWTManager, get_jwt_identity, verify_jwt_in_request
import psycopg2
import os
from flask_cors import CORS
import secrets

# Initialize Flask app
app = Flask(__name__)
CORS(app, supports_credentials=True,origins=["http://localhost:3000"])
app.config["JWT_SECRET_KEY"] = "supersecretkey"  # Change this in production!

app.config["JWT_TOKEN_LOCATION"] = ["cookies"]  # ✅ Look for JWTs in cookies instead of headers
app.config["JWT_COOKIE_SECURE"] = True  # Set to True in production (requires HTTPS)
app.config["JWT_ACCESS_COOKIE_NAME"] = "access_token"  # The cookie storing the access token
app.config["JWT_REFRESH_COOKIE_NAME"] = "refresh_token"  # The cookie storing the refresh token
app.config["JWT_COOKIE_CSRF_PROTECT"] = False 

jwt = JWTManager(app)

bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# Database Connection
DB_NAME = "ipl_db"
DB_USER = "postgres"
DB_PASSWORD = "13052000"
DB_HOST = "localhost"
DB_PORT = "5432"

DATABASE_URL = os.getenv("DATABASE_URL")

def get_db_connection():
    return psycopg2.connect(DATABASE_URL)
    return psycopg2.connect(
        database=DB_NAME, user=DB_USER, password=DB_PASSWORD, host=DB_HOST, port=DB_PORT
    )


@app.route("/problem/<int:problem_id>", methods=["GET"])
def get_problem(problem_id):
    """Fetch a single problem along with correct schema of matches and deliveries tables."""
    conn = get_db_connection()
    cur = conn.cursor()

    # Fetch problem details
    cur.execute("SELECT id, question, type FROM questions WHERE id = %s;", (problem_id,))
    problem = cur.fetchone()

    if not problem:
        conn.close()
        return jsonify({"error": "Problem not found"}), 404

    # Define tables we want to return
    tables = ["matches", "deliveries"]
    table_data = {}

    # Fetch table columns in correct order & fetch sample rows
    for table in tables:
        cur.execute(f"SELECT column_name FROM information_schema.columns WHERE table_name = '{table}' ORDER BY ordinal_position;")
        columns = [row[0] for row in cur.fetchall()]

        cur.execute(f"SELECT {', '.join(columns)} FROM {table} LIMIT 3;")  # Ensures correct column order
        rows = cur.fetchall()

        table_data[table] = {
            "columns": columns,
            "sample_data": rows  # This now aligns correctly
        }

    conn.close()

    return jsonify({
        "problem": {
            "id": problem[0],
            "question": problem[1],
            "type": problem[2],
        },
        "tables": table_data
    })

# ✅ User Registration (Signup)
@app.route("/register", methods=["POST"])
def register():
    data = request.get_json()
    username = data.get("username")
    email = data.get("email")
    password = data.get("password")

    if not username or not email or not password:
        return jsonify({"error": "All fields are required"}), 400

    hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")

    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO users (username, email, password_hash) VALUES (%s, %s, %s) RETURNING id;",
            (username, email, hashed_password),
        )
        user_id = cur.fetchone()[0]
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({"message": "User registered successfully", "user_id": user_id}), 201
    except psycopg2.IntegrityError:
        return jsonify({"error": "Username or email already exists"}), 409
    except Exception as e:
        return jsonify({"error": str(e)}), 500


def generate_csrf_token():
    return secrets.token_hex(32)  # 64-character random string
# ✅ User Login (JWT Token Generation)
@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400

    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT id, password_hash FROM users WHERE email = %s;", (email,))
        user = cur.fetchone()
        cur.close()
        conn.close()

        if user and bcrypt.check_password_hash(user[1], password):
            access_token = create_access_token(identity=str(user[0]))  # Convert user ID to string
            refresh_token = create_refresh_token(identity=str(user[0]))
            csrf_token = generate_csrf_token()
            response = make_response(jsonify({"message": "Login successful"}))
            response.set_cookie(
            "access_token", access_token,
            httponly=True, samesite="None", secure=True  # Secure=True for HTTPS
            )
            response.set_cookie(
            "refresh_token", refresh_token,
            httponly=True, samesite="None", secure=True
            )
            response.set_cookie("csrf_token", csrf_token, httponly=False, secure=True, samesite="None")
            return response
        else:
            return jsonify({"error": "Invalid email or password"}), 401

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/health", methods=["GET"])
def health_check():
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT 1;")  # Simple query to check DB connection
        cur.close()
        conn.close()
        return jsonify({"status": "ok", "message": "Service and database are running"}), 200
    except Exception as e:
        return jsonify({"status": "error", "message": "Database connection failed", "error": str(e)}), 500



# ✅ Refresh Token Endpoint
@app.route("/refresh", methods=["POST"])
@jwt_required(refresh=True)  # Requires a valid refresh token
def refresh():
    current_user = get_jwt_identity()
    new_access_token = create_access_token(identity=current_user)
    return jsonify({"access_token": new_access_token}), 200


# ✅ Get User Profile
@app.route("/profile", methods=["GET"])
@jwt_required()
def get_profile():
    user_id = get_jwt_identity()

    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # Fetch user details
        cur.execute("SELECT username, email FROM users WHERE id = %s;", (user_id,))
        user = cur.fetchone()

        if not user:
            return jsonify({"error": "User not found"}), 404

        # Fetch user statistics
        cur.execute("""
            SELECT COUNT(*) AS total_submissions,
                   SUM(CASE WHEN is_correct THEN 1 ELSE 0 END) AS correct_submissions,
                   COUNT(DISTINCT question_id) AS unique_questions_solved
            FROM user_answers WHERE user_id = %s;
        """, (user_id,))
        
        stats = cur.fetchone()
        cur.close()
        conn.close()

        return jsonify({
            "username": user[0],
            "email": user[1],
            "total_submissions": stats[0],
            "correct_submissions": stats[1],
            "unique_questions_solved": stats[2]
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ✅ Submit SQL Answer

# ✅ Protected Route (Only Accessible with JWT Token)
@app.route("/protected", methods=["GET"])
@jwt_required()
def protected():
    return jsonify({"message": "You have access to this protected route!"}), 200


@app.route("/csrf-token", methods=["GET"])
def get_csrf_token():
    csrf_token = request.cookies.get("csrf_token")
    if not csrf_token:
        return jsonify({"error": "No CSRF token found"}), 403
    return jsonify({"csrf_token": csrf_token})


@app.route("/submit-answer", methods=["POST"])
@jwt_required()
def submit_answer():
    csrf_token_cookie = request.cookies.get("csrf_token")
    csrf_token_header = request.headers.get("X-CSRF-Token")

    if not csrf_token_cookie or not csrf_token_header or csrf_token_cookie != csrf_token_header:
        return jsonify({"error": "CSRF token mismatch"}), 403  # 🚨 CSRF validation failed
    data = request.get_json()
    question_id = data.get("question_id")
    user_query = data.get("user_query")
    is_submit = data.get("is_submit", False)  # Submission check

    if not question_id or not user_query:
        return jsonify({"error": "Question ID and SQL query are required"}), 400

    user_id = None
    if is_submit:
        # ✅ Ensure User is Authenticated for Submissions
        try:
            user_id = get_jwt_identity()
            if not user_id:
                return jsonify({"error": "Unauthorized"}), 401
        except Exception as e:
            return jsonify({"error": "JWT Invalid", "details": str(e)}), 401

    conn = None  # Initialize connection
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # ✅ Fetch correct query from DB
        cur.execute("SELECT correct_query FROM questions WHERE id = %s;", (question_id,))
        correct_query = cur.fetchone()

        if not correct_query:
            return jsonify({"error": "Invalid question ID"}), 400
        correct_query = correct_query[0]

        # ✅ Execute correct query
        cur.execute(correct_query)
        correct_result = cur.fetchall()

        # ✅ Execute user's SQL query
        try:
            cur.execute(user_query)
            user_result = cur.fetchall()
        except Exception as e:
            return jsonify({
                "error": "Invalid SQL query",
                "details": str(e),
                "user_query_result": None,
                "correct_query_result": correct_result
            }), 400

        # ✅ Compare results
        is_correct = user_result == correct_result

        # ✅ Store the answer only if it's a submission
        if is_submit and user_id:
            cur.execute("""
                INSERT INTO user_answers (user_id, question_id, user_query, is_correct)
                VALUES (%s, %s, %s, %s)
            """, (user_id, question_id, user_query, is_correct))
            conn.commit()

        return jsonify({
            "message": "Query executed successfully" if not is_submit else "Answer submitted successfully",
            "is_correct": is_correct,
            "user_query_result": user_result,
            "correct_query_result": correct_result
        }), 201

    except Exception as e:
        return jsonify({"error": str(e)}), 500

    finally:
        if conn:
            conn.close()  # ✅ Always close DB connection


@app.route("/run-answer", methods=["POST"])
def run_answer():
    user_id = ""
    
    data = request.get_json()
    
    question_id = data.get("question_id")
    user_query = data.get("user_query")
    is_submit = data.get("is_submit", False)  # Key from frontend to check if it's a submission
    if is_submit:
        user_id = get_jwt_identity()
    if not question_id or not user_query:
        return jsonify({"error": "Question ID and SQL query are required"}), 400

    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # Fetch the expected correct query from the database
        cur.execute("SELECT correct_query FROM questions WHERE id = %s;", (question_id,))
        correct_query = cur.fetchone()

        if not correct_query:
            return jsonify({"error": "Invalid question ID"}), 400
        correct_query = correct_query[0]

        # Execute the correct query
        cur.execute(correct_query)
        correct_result = cur.fetchall()

        # Execute the user-submitted query
        try:
            cur.execute(user_query)
            user_result = cur.fetchall()
        except Exception as e:
            return jsonify({
                "error": "Invalid SQL query",
                "details": str(e),
                "user_query_result": None,
                "correct_query_result": correct_result
            }), 400

        # Compare results
        is_correct = user_result == correct_result  # True if answers match

        # Only store the answer if it's a submission
        if is_submit:
            cur.execute("""
                INSERT INTO user_answers (user_id, question_id, user_query, is_correct)
                VALUES (%s, %s, %s, %s)
            """, (user_id, question_id, user_query, is_correct))
            conn.commit()

        cur.close()
        conn.close()

        return jsonify({
            "message": "Query executed successfully" if not is_submit else "Answer submitted successfully",
            "is_correct": is_correct,
            "user_query_result": user_result,
            "correct_query_result": correct_result
        }), 201

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ✅ Fetch User Submissions


@app.route("/submissions", methods=["GET"])
@jwt_required()
def get_submissions():
    user_id = get_jwt_identity()
    question_id = request.args.get("question_id")  # Get question_id from query params

    try:
        conn = get_db_connection()
        cur = conn.cursor()

        if question_id:
            # Fetch submissions only for the given question_id
            cur.execute("""
                SELECT q.id, q.question, ua.user_query, ua.is_correct, ua.submitted_at 
                FROM user_answers ua
                JOIN questions q ON ua.question_id = q.id
                WHERE ua.user_id = %s AND q.id = %s
                ORDER BY ua.submitted_at DESC
            """, (user_id, question_id))
        else:
            # Fetch all submissions for the user
            cur.execute("""
                SELECT q.id, q.question, ua.user_query, ua.is_correct, ua.submitted_at 
                FROM user_answers ua
                JOIN questions q ON ua.question_id = q.id
                WHERE ua.user_id = %s
                ORDER BY ua.submitted_at DESC
            """, (user_id,))

        submissions = cur.fetchall()
        cur.close()
        conn.close()

        return jsonify({"submissions": submissions}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/challenges", methods=["GET"])
def get_challenges():
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # Fetch questions from the database
        cur.execute("SELECT id, question, type FROM questions;")
        challenges = cur.fetchall()
        cur.close()
        conn.close()

        # Convert to JSON format
        challenge_list = [
            {"id": q[0], "question": q[1], "type": q[2]} for q in challenges
        ]
        
        return jsonify({"challenges": challenge_list}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ✅ Fetch User Progress (Total Questions Attempted)
@app.route("/progress", methods=["GET"])
@jwt_required()
def get_progress():
    user_id = get_jwt_identity()

    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        cur.execute("""
            SELECT COUNT(DISTINCT question_id) AS questions_attempted, 
                   SUM(CASE WHEN is_correct THEN 1 ELSE 0 END) AS correct_answers
            FROM user_answers
            WHERE user_id = %s
        """, (user_id,))
        
        progress = cur.fetchone()
        cur.close()
        conn.close()

        return jsonify({
            "questions_attempted": progress[0],
            "correct_answers": progress[1]
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# Run Flask Server
if __name__ == "__main__":
    app.run(debug=True)
