from flask import Flask, request, jsonify
from flask_bcrypt import Bcrypt
from flask_jwt_extended import create_access_token, jwt_required, JWTManager, get_jwt_identity
import psycopg2
import os
from flask_cors import CORS


# Initialize Flask app
app = Flask(__name__)
CORS(app, origins=["http://localhost:3000"])
app.config["JWT_SECRET_KEY"] = "supersecretkey"  # Change this in production!

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
            return jsonify({"message": "Login successful", "token": access_token}), 200
        else:
            return jsonify({"error": "Invalid email or password"}), 401

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ✅ Protected Route (Only Accessible with JWT Token)
@app.route("/protected", methods=["GET"])
@jwt_required()
def protected():
    return jsonify({"message": "You have access to this protected route!"}), 200


@app.route("/submit-answer", methods=["POST"])
@jwt_required()
def submit_answer():
    user_id = get_jwt_identity()  # Get user ID from JWT
    data = request.get_json()
    question_id = data.get("question_id")
    user_query = data.get("user_query")

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

        # Store the answer submission with evaluation result
        cur.execute("""
            INSERT INTO user_answers (user_id, question_id, user_query, is_correct)
            VALUES (%s, %s, %s, %s)
        """, (user_id, question_id, user_query, is_correct))

        conn.commit()
        cur.close()
        conn.close()

        return jsonify({
            "message": "Answer submitted successfully",
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

    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
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
