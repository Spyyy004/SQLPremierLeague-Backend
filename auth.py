import hashlib
import hmac
from flask import Flask, request, jsonify, make_response
from flask_bcrypt import Bcrypt
from flask_jwt_extended import create_access_token, jwt_required, create_refresh_token, JWTManager, get_jwt_identity, verify_jwt_in_request
from psycopg2 import pool
import os
from flask_cors import CORS
import secrets
from datetime import time
import datetime
import psycopg2
from standardwebhooks import Webhook
import re
import json
from datetime import time
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
import time as timer
from sql_metadata import Parser
import uuid

# Initialize Flask app
app = Flask(__name__)
CORS(app, supports_credentials=True,resources={r"/*": {"origins": ["https://sqlpremierleague.com", "http://localhost:3000"]}})
app.config["JWT_SECRET_KEY"] = "supersecretkey"  # Change this in production!

app.config["JWT_TOKEN_LOCATION"] = ["cookies"]  # ✅ Look for JWTs in cookies instead of headers
app.config["JWT_COOKIE_SECURE"] = True  # Set to True in production (requires HTTPS)
app.config["JWT_ACCESS_COOKIE_NAME"] = "access_token"  # The cookie storing the access token
app.config["JWT_REFRESH_COOKIE_NAME"] = "refresh_token"  # The cookie storing the refresh token
app.config["JWT_COOKIE_CSRF_PROTECT"] = False 

app.config.update(
    SESSION_COOKIE_SAMESITE="None",  # Allows cross-site cookies
    SESSION_COOKIE_SECURE=True,      # Required for SameSite=None
)

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
DODO_SECRET = os.getenv("DODO_SECRET")
def get_db_connection():
    try:
        conn = psycopg2.connect(DATABASE_URL)  # Direct connection without pooling
        print("✅ Database connection established successfully!")
        return conn
    except Exception as e:
        print(f"❌ Error connecting to the database: {e}")
        return None


@app.route("/challenge-of-the-day", methods=["GET"])
def challenge_of_the_day():
    conn = get_db_connection()
    if not conn:
        return jsonify({"error": "Database connection failed"}), 500

    try:
        cur = conn.cursor()
        today = datetime.date.today()

        # ✅ Check if today's challenge is already set
        cur.execute("SELECT challenge_id FROM daily_challenge WHERE challenge_date = %s;", (today,))
        challenge = cur.fetchone()

        if challenge:
            challenge_id = challenge[0]
        else:
            # ✅ Get yesterday's challenge to ensure a new one is selected
            cur.execute("SELECT challenge_id FROM daily_challenge WHERE challenge_date = %s;", (today - datetime.timedelta(days=1),))
            yesterday_challenge = cur.fetchone()
            yesterday_id = yesterday_challenge[0] if yesterday_challenge else None

            # ✅ Fix: Use `COALESCE(NULL, -1)` to prevent NULL issues
            cur.execute("SELECT id FROM questions WHERE id != COALESCE(%s, -1) ORDER BY RANDOM() LIMIT 1;", (yesterday_id,))
            challenge_data = cur.fetchone()

            if not challenge_data:
                return jsonify({"error": "No available challenges"}), 404

            challenge_id = challenge_data[0]

            # ✅ Insert today's challenge
            cur.execute("INSERT INTO daily_challenge (challenge_date, challenge_id) VALUES (%s, %s);", (today, challenge_id))
            conn.commit()

        # ✅ Fetch challenge details
        cur.execute("SELECT id, question, type, category FROM questions WHERE id = %s;", (challenge_id,))
        challenge_data = cur.fetchone()
        conn.close()

        if not challenge_data:
            return jsonify({"error": "Challenge not found"}), 404

        return jsonify({
            "id": challenge_data[0],
            "question": challenge_data[1],
            "type": challenge_data[2],
            "category": challenge_data[3]
        })

    except Exception as e:
        print("❌ API Error:", str(e))
        return jsonify({"error": "Internal server error", "details": str(e)}), 500


def extract_table_data(tables):
    """
    Fetch schema and sample data for given tables.
    """
    conn = get_db_connection()
    cur = conn.cursor()
    table_data = {}

    for table in tables:
        try:
            cur.execute("""
                SELECT column_name, data_type 
                FROM information_schema.columns 
                WHERE table_name = %s 
                ORDER BY ordinal_position;
            """, (table,))
            
            columns_info = cur.fetchall()
            columns = [col[0] for col in columns_info]

            if not columns:
                continue  

            cur.execute(f"SELECT {', '.join(columns)} FROM {table} LIMIT 3;")
            rows = cur.fetchall()

            formatted_rows = [
                [value.strftime("%H:%M:%S") if isinstance(value, datetime.time) else value for value in row]
                for row in rows
            ]

            table_data[table] = {"columns": columns, "sample_data": formatted_rows}

        except Exception as table_error:
            print(f"Error fetching table data for {table}: {table_error}")

    cur.close()
    conn.close()
    return table_data

@app.route("/problem/<int:problem_id>", methods=["GET"])
def get_problem(problem_id):
    """Fetch problem details along with hints and necessary table data."""
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # ✅ Fetch problem details along with the correct query
        cur.execute("""
            SELECT id, question, type, category, correct_query 
            FROM questions 
            WHERE id = %s;
        """, (problem_id,))
        problem = cur.fetchone()

        if not problem:
            conn.close()
            return jsonify({"error": "Problem not found"}), 404

        problem_id, question, type_, category, correct_query = problem

        if not correct_query:
            return jsonify({"error": "No correct query found for this problem"}), 400

        # ✅ Extract table names dynamically from the correct SQL query
        required_tables = extract_table_names(correct_query)

        if not required_tables:
            return jsonify({"error": "No tables detected in correct query"}), 400

        table_data = {}

        for table in required_tables:
            try:
                # ✅ Fetch column names & data types
                cur.execute("""
                    SELECT column_name, data_type 
                    FROM information_schema.columns 
                    WHERE table_name = %s 
                    ORDER BY ordinal_position;
                """, (table,))
                
                columns_info = cur.fetchall()
                columns = [col[0] for col in columns_info]

                if not columns:
                    raise Exception(f"Table '{table}' has no columns or does not exist.")

                # ✅ Fetch sample data (limit 3 rows)
                cur.execute(f"SELECT {', '.join(columns)} FROM {table} LIMIT 3;")
                rows = cur.fetchall()

                # ✅ Convert TIME columns to string format
                formatted_rows = [
                    [value.strftime("%H:%M:%S") if isinstance(value, time) else value for value in row]
                    for row in rows
                ]

                table_data[table] = {"columns": columns, "sample_data": formatted_rows}

            except Exception as table_error:
                return jsonify({"error": f"Failed fetching data for table {table}: {str(table_error)}"}), 500

        # ✅ Fetch Hints for the Question
        cur.execute("""
            SELECT hint_text 
            FROM question_hints 
            WHERE question_id = %s 
            ORDER BY hint_order;
        """, (problem_id,))
        hints = [row[0] for row in cur.fetchall()]

        conn.close()

        return jsonify({
            "problem": {
                "id": problem_id,
                "question": question,
                "type": type_,
                "category": category,
                "hints": hints
            },
            "tables": table_data
        })

    except Exception as e:
        return jsonify({"error": f"Internal Server Error: {str(e)}"}), 500


# @app.route("/problem/<int:problem_id>", methods=["GET"])
# def get_problem(problem_id):
#     """Fetch problem details and return only the necessary tables used in the correct_query."""
#     try:
#         conn = get_db_connection()
#         cur = conn.cursor()

#         # ✅ Fetch problem details along with the correct query
#         cur.execute("SELECT id, question, type, category, correct_query FROM questions WHERE id = %s;", (problem_id,))
#         problem = cur.fetchone()

#         if not problem:
#             conn.close()
#             return jsonify({"error": "Problem not found"}), 404

#         problem_id, question, type_, category, correct_query = problem

#         if not correct_query:
#             return jsonify({"error": "No correct query found for this problem"}), 400

#         # ✅ Extract table names dynamically from the correct SQL query
#         required_tables = extract_table_names(correct_query)

#         if not required_tables:
#             return jsonify({"error": "No tables detected in correct query"}), 400

#         table_data = {}

#         for table in required_tables:
#             try:
#                 # ✅ Fetch column names & data types
#                 cur.execute("""
#                     SELECT column_name, data_type 
#                     FROM information_schema.columns 
#                     WHERE table_name = %s 
#                     ORDER BY ordinal_position;
#                 """, (table,))
                
#                 columns_info = cur.fetchall()
#                 columns = [col[0] for col in columns_info]

#                 if not columns:
#                     raise Exception(f"Table '{table}' has no columns or does not exist.")

#                 # ✅ Fetch sample data (limit 3 rows)
#                 cur.execute(f"SELECT {', '.join(columns)} FROM {table} LIMIT 3;")
#                 rows = cur.fetchall()

#                 # ✅ Convert TIME columns to string format
#                 formatted_rows = [
#                     [value.strftime("%H:%M:%S") if isinstance(value, time) else value for value in row]
#                     for row in rows
#                 ]

#                 table_data[table] = {"columns": columns, "sample_data": formatted_rows}

#             except Exception as table_error:
#                 return jsonify({"error": f"Failed fetching data for table {table}: {str(table_error)}"}), 500

#         conn.close()

#         return jsonify({
#             "problem": {"id": problem_id, "question": question, "type": type_, "category": category},
#             "tables": table_data
#         })

#     except Exception as e:
#         return jsonify({"error": f"Internal Server Error: {str(e)}"}), 500

def fetch_question_with_schema(difficulty):
    """
    Fetch a random SQL question with associated table schema & sample data.
    """
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT id, question, type, category, correct_query
        FROM questions WHERE type = %s ORDER BY RANDOM() LIMIT 1;
    """, (difficulty,))
    question = cur.fetchone()

    if not question:
        return None

    question_data = {
        "id": question[0],
        "question": question[1],
        "type": question[2],
        "category": question[3],
        "correct_query": question[4],
        "tables": {}
    }

    required_tables = extract_table_names(question[4])
    question_data["tables"] = extract_table_data(required_tables)

    cur.close()
    conn.close()
    return question_data

@app.route("/start-test", methods=["POST"])
def start_test():
    """
    Starts a new SQL test and creates a test session.
    """
    try:
        # Get user_id if logged in
        user_id = None
        try:
            verify_jwt_in_request(optional=True)
            user_id = get_jwt_identity()
        except:
            pass

        conn = get_db_connection()
        cur = conn.cursor()

        # Create new test session
        test_session_id = str(uuid.uuid4())
        cur.execute("""
            INSERT INTO test_sessions (id, user_id, status)
            VALUES (%s, %s, 'in_progress')
            RETURNING id;
        """, (test_session_id, user_id))
        conn.commit()

        # Fetch initial questions
        first_question = fetch_question_with_schema("easy")
        second_question = fetch_question_with_schema("easy")
        third_question = fetch_question_with_schema("medium")

        return jsonify({
            "test_session_id": test_session_id,
            "questions": [first_question, second_question, third_question],
        }), 200

    except Exception as e:
        print("Error in start_test:", str(e))
        return jsonify({"error": "Internal server error"}), 500
    finally:
        if conn:
            conn.close()


@app.route("/next-question", methods=["POST"])
def next_question():
    """
    Returns 2 new questions with table schemas based on:
    - Whether the last answer was correct
    - How many total correct answers the user has given
    - Gradual difficulty progression based on score
    """
    data = request.get_json()
    test_id = data.get("test_id")  # 🔥 Ensure test_id is provided
    answered_correctly = data.get("correct")
    score = data.get("score")  # 🔥 Track score in the request
    correct_answers = data.get("correct_answers")  # 🔥 Track how many correct answers

    if not test_id:
        return jsonify({"error": "Test ID is required"}), 400
    if score is None or correct_answers is None:
        return jsonify({"error": "Score and correct answers count are required"}), 400

    # 🔥 Adjust difficulty based on overall progress
    if score < 20:
        difficulty = "easy"  # 🔥 Keep showing easy questions initially
    elif 20 <= score < 40:
        difficulty = "medium" if answered_correctly else "easy"  # 🔥 Introduce medium questions
    elif 50 <= score < 70:
        difficulty = "medium" if answered_correctly else "medium"  # 🔥 Mostly medium questions
    else:
        difficulty = "hard" if answered_correctly else "medium"  # 🔥 Gradual increase to hard

    # ✅ Fetch two new questions dynamically
    next_question = fetch_question_with_schema(difficulty)
    backup_question = fetch_question_with_schema("medium" if difficulty == "hard" else "easy")

    return jsonify({
        "test_id": test_id,  # 🔥 Return test_id for tracking
        "questions": [next_question, backup_question],
    }), 200

def assign_badge(correct_answers, total_questions):
    """
    Assign a badge based on the user's performance.
    Requires a minimum number of questions answered to qualify for higher badges.
    """
    if total_questions < 5:
        return "Try"  # Not enough questions answered for higher badges

    accuracy = correct_answers / total_questions if total_questions > 0 else 0

    if accuracy >= 0.8:
        return "Wizard"
    elif accuracy >= 0.5:
        return "Intermediate"
    else:
        return "Beginner"
    

@app.route("/end-test", methods=["POST"])
@jwt_required(optional=True)
def end_test():
    """
    Ends the test and provides comprehensive results.
    Full results are only shown to logged-in users.
    """
    user_id = get_jwt_identity()
    data = request.get_json()
    test_session_id = data.get("test_session_id")

    if not test_session_id:
        return jsonify({"error": "Test session ID is required"}), 400

    try:
        print(f"Received request to end test for session ID: {test_session_id} by user: {user_id}")

        conn = get_db_connection()
        cur = conn.cursor()

        # Check if the test session exists
        cur.execute("""
            SELECT status 
            FROM test_sessions 
            WHERE id = %s;
        """, (test_session_id,))
        
        test_session = cur.fetchone()
        
        if not test_session:
            return jsonify({"error": "Test session not found"}), 404

        # Get all attempts for this test session
        cur.execute("""
            SELECT 
                q.id,
                q.question,
                q.type,
                q.category,
                q.correct_query,
                ta.user_query,
                ta.is_correct,
                ta.execution_time
            FROM test_attempts ta
            JOIN questions q ON ta.question_id = q.id
            WHERE ta.test_session_id = %s
            ORDER BY ta.attempted_at;
        """, (test_session_id,))
        
        attempts = cur.fetchall()

        if not attempts:
            return jsonify({"error": "No attempts found for this test session"}), 404

        # Calculate score and statistics
        total_questions = len(attempts)
        correct_answers = sum(1 for attempt in attempts if attempt[6])  # is_correct
        score = round((correct_answers / total_questions) * 100)
        
        badge = assign_badge(correct_answers=correct_answers, total_questions=total_questions)

        # Update test session with final results
        
       

        if user_id:
            cur.execute("""
            UPDATE test_sessions 
            SET status = 'completed', 
                end_time = NOW(),
                score = %s,
                badge = %s,
                user_id = %s
            WHERE id = %s;
        """, (score, badge, user_id, test_session_id))
            # For logged-in users: provide full details
            question_details = [{
                "question_id": attempt[0],
                "question_text": attempt[1],
                "type": attempt[2],
                "category": attempt[3],
                "correct_query": attempt[4],
                "user_query": attempt[5],
                "is_correct": attempt[6],
                "execution_time": attempt[7]
            } for attempt in attempts]

            response_data = {
                "test_summary": {
                    "test_session_id": test_session_id,
                    "score": score,
                    "badge": badge,
                    "total_questions": total_questions,
                    "correct_answers": correct_answers,
                    "accuracy": round((correct_answers / total_questions * 100), 2)
                },
                "question_details": question_details,
                "message": "Test completed successfully!",
                "user_id": user_id
            }
        else:
            cur.execute("""
            UPDATE test_sessions 
            SET status = 'pending_claim', 
                end_time = NOW(),
                score = %s,
                badge = %s,
                user_id = %s
            WHERE id = %s;
        """, (score, badge, user_id, test_session_id))
            response_data = {
                "message": "Please log in to view full results",
                "preview": {
                    "test_session_id": test_session_id,
                    "score": score,
                    "total_questions": total_questions,
                    "correct_answers": correct_answers,
                     "user_id": user_id
                }
            }

        conn.commit()
        return jsonify(response_data), 200

    except Exception as e:
        print("Error in end_test:", str(e))  # Log the error
        return jsonify({"error": "Internal server error", "details": str(e)}), 500
    finally:
        if conn:
            conn.close()

def compare_query_results(cur, user_query, question_id):
    """Helper function to compare query results"""
    # Get correct query
    cur.execute("SELECT correct_query FROM questions WHERE id = %s;", (question_id,))
    correct_query = cur.fetchone()[0]

    # Execute correct query
    cur.execute(correct_query)
    correct_result = cur.fetchall()

    # Execute user query
    cur.execute(user_query)
    user_result = cur.fetchall()

    # Compare results
    is_correct = user_result == correct_result

    return is_correct, user_result, correct_result
def extract_table_names(sql_query):
    """
    Extracts table names from SQL queries safely using `sql_metadata`.
    - Handles JOINs, subqueries, CTEs, and aliases.
    """
    try:
        parser = Parser(sql_query)
        tables = parser.tables
        return list(tables)  # Convert to list for JSON response
    except Exception as e:
        print(f"Error extracting tables: {str(e)}")
        return []

@app.route("/edit-profile", methods=["PUT"])
@jwt_required()  # Requires user authentication
def edit_profile():
    user_id = get_jwt_identity()  # Get the authenticated user's ID
    data = request.get_json()

    new_username = data.get("username")
    new_password = data.get("password")

    if not new_username and not new_password:
        return jsonify({"error": "At least one field (username or password) must be provided"}), 400

    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # ✅ If updating username, check if it's already taken
        if new_username:
            cur.execute("SELECT id FROM users WHERE username = %s AND id != %s;", (new_username, user_id))
            if cur.fetchone():
                return jsonify({"error": "Username already taken"}), 409  # Conflict

        # ✅ Update fields dynamically
        update_fields = []
        values = []

        if new_username:
            update_fields.append("username = %s")
            values.append(new_username)

        if new_password:
            hashed_password = bcrypt.generate_password_hash(new_password).decode("utf-8")
            update_fields.append("password_hash = %s")
            values.append(hashed_password)

        values.append(user_id)  # Add user_id for WHERE condition

        query = f"UPDATE users SET {', '.join(update_fields)} WHERE id = %s RETURNING username;"
        cur.execute(query, tuple(values))
        updated_user = cur.fetchone()

        conn.commit()
        cur.close()
        conn.close()

        return jsonify({"message": "Profile updated successfully", "username": updated_user[0]}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500  # Internal Server Error

@app.route("/register",methods=["POST"])
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




def is_safe_query(query):
    """Check if the query is safe before execution."""
    query = query.strip().lower()

    # **Allowed pattern: SELECT statements only**
    if not query.startswith("select"):
        return False  # ✅ Query must start with SELECT

    # **🚨 Forbidden keywords to prevent data modification**
    forbidden_keywords = ['delete', 'update', 'drop', 'insert', 'alter', 'truncate', 'create', 'replace', 'grant', 'revoke']
    if any(keyword in query for keyword in forbidden_keywords):
        return False  # ❌ Block dangerous operations

    # **🚨 Strictly Restrict Access to Sensitive Tables**
    restricted_tables = ['users', 'user_answers', 'tokens', 'admin_logs', 'auth_sessions']
    pattern = re.compile(rf"\b({'|'.join(restricted_tables)})\b", re.IGNORECASE)

    if pattern.search(query):
        return False  # ❌ Block access to restricted tables

    return True  # ✅ Query is safe to execute

@app.route("/categories", methods=["GET"])
def get_categories():
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # ✅ Fetch categories and count of questions for each category
        cur.execute("""
            SELECT category, COUNT(*) AS question_count 
            FROM questions 
            GROUP BY category;
        """)
        
        categories = cur.fetchall()
        cur.close()
        conn.close()

        # ✅ Format response
        category_list = [{"category": row[0], "question_count": row[1]} for row in categories]

        return jsonify({"categories": category_list}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/logout', methods=['POST'])
def logout():
    response = make_response(jsonify({"message": "Logged out successfully"}))
    # Clear the access token cookie
    response.set_cookie(
        "access_token", value="", expires=0,
        httponly=True, secure=True, samesite="None"
    )
    # Clear the refresh token cookie
    response.set_cookie(
        "refresh_token", value="", expires=0,
        httponly=True, secure=True, samesite="None"
    )
    # Optionally clear the CSRF token cookie if you're managing it client-side
    response.set_cookie(
        "csrf_token", value="", expires=0,
        httponly=False, secure=True, samesite="None"
    )
    return response


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
            user_id = str(user[0])
            access_token = create_access_token(identity=str(user[0]))  # Convert user ID to string
            refresh_token = create_refresh_token(identity=str(user[0]))
            csrf_token = generate_csrf_token()
            response = make_response(jsonify({"message": "Login successful","user_id":user_id}))
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
    response = make_response(jsonify({"message": "Login successful"}))
    response.set_cookie(
            "access_token", new_access_token,
            httponly=True, samesite="None", secure=True  # Secure=True for HTTPS
            )
    return response


@app.route("/profile", methods=["GET"])
@jwt_required()
def get_profile():
    user_id = get_jwt_identity()

    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # ✅ Fetch user details, XP, and account creation date
        cur.execute("SELECT username, email, xp, created_at FROM users WHERE id = %s;", (user_id,))
        user = cur.fetchone()

        if not user:
            return jsonify({"error": "User not found"}), 404

        username, email, xp, created_at = user

        # ✅ Fetch user statistics (total submissions, correct answers, unique questions solved)
        cur.execute("""
            SELECT COUNT(*) AS total_submissions,
                   SUM(CASE WHEN is_correct THEN 1 ELSE 0 END) AS correct_submissions,
                   COUNT(DISTINCT question_id) AS unique_questions_solved
            FROM user_answers WHERE user_id = %s;
        """, (user_id,))
        stats = cur.fetchone()
        total_submissions, correct_submissions, unique_questions_solved = stats

        # ✅ Calculate accuracy (handle zero submissions case)
        accuracy = round((correct_submissions / total_submissions) * 100, 2) if total_submissions > 0 else 0

        # ✅ Fetch user rank (Leaderboard Position)
        cur.execute("""
            SELECT rank FROM (
                SELECT id, username, xp, RANK() OVER (ORDER BY xp DESC) AS rank
                FROM users
            ) ranked_users
            WHERE id = %s;
        """, (user_id,))
        rank_result = cur.fetchone()
        user_rank = rank_result[0] if rank_result else None

        # ✅ Fetch fastest query execution time
        cur.execute("""
            SELECT MIN(execution_time) FROM user_answers WHERE user_id = %s;
        """, (user_id,))
        fastest_time = cur.fetchone()[0]

        # ✅ Fetch recent activity (last 3 submissions)
        cur.execute("""
            SELECT q.question, ua.submitted_at 
            FROM user_answers ua
            JOIN questions q ON ua.question_id = q.id
            WHERE ua.user_id = %s
            ORDER BY ua.submitted_at DESC
            LIMIT 3;
        """, (user_id,))
        recent_activity = [{"question": row[0], "submitted_at": row[1]} for row in cur.fetchall()]

        # ✅ Fetch daily streak (consecutive days of activity)
        cur.execute("""
            WITH user_dates AS (
                SELECT DISTINCT DATE(submitted_at) AS submission_date
                FROM user_answers
                WHERE user_id = %s
            )
            SELECT COUNT(*) FROM user_dates 
            WHERE submission_date >= CURRENT_DATE - INTERVAL '7 days';
        """, (user_id,))
        daily_streak = cur.fetchone()[0]

        # ✅ Fetch all badges earned by the user
        cur.execute("""
            SELECT badge_name, awarded_at
            FROM user_badges
            WHERE user_id = %s
            ORDER BY awarded_at DESC;
        """, (user_id,))
        badges = [{"badge_name": row[0], "awarded_at": row[1]} for row in cur.fetchall()]

        cur.close()
        conn.close()

        return jsonify({
            "username": username,
            "email": email,
            "xp": xp,
            "total_submissions": total_submissions,
            "correct_submissions": correct_submissions,
            "unique_questions_solved": unique_questions_solved,
            "accuracy": accuracy,
            "rank": user_rank,
            "fastest_query_time": fastest_time,
            "recent_activity": recent_activity,
            "daily_streak": daily_streak,
            "badges": badges,  # ✅ Added badges list
            "member_since": created_at.strftime("%B %Y")  # Format as "March 2025"
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/quests", methods=["GET"])
@jwt_required(optional=True)
def get_quests():
    """Retrieve all quests available to the user."""
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # Fetch all quests
        cur.execute("SELECT id, name, description, difficulty FROM quests ORDER BY difficulty, id;")
        quests = [{"id": row[0], "name": row[1], "description": row[2], "difficulty": row[3]} for row in cur.fetchall()]

        cur.close()
        conn.close()
        return jsonify({"quests": quests}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

def serialize_value(value):
    """Converts PostgreSQL data types to JSON serializable formats."""
    if isinstance(value, datetime.date):  
        return value.strftime("%Y-%m-%d")  # Format DATE values
    elif isinstance(value, datetime.time):
        return value.strftime("%H:%M:%S")  # Format TIME values
    return value  # Return as is if no conversion is needed

# ✅ 2. Fetch details of a specific quest
@app.route("/quests/<int:quest_id>", methods=["GET"])
@jwt_required(optional=True)
def get_quest_details(quest_id):
    """Retrieve details of a specific quest, including full question details."""
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # Fetch quest details
        cur.execute("SELECT id, name, description, difficulty FROM quests WHERE id = %s;", (quest_id,))
        quest = cur.fetchone()
        if not quest:
            return jsonify({"error": "Quest not found"}), 404

        quest_data = {
            "id": quest[0],
            "name": quest[1],
            "description": quest[2],
            "difficulty": quest[3],
            "questions": []
        }

        # Fetch questions associated with the quest
        cur.execute("""
            SELECT q.id, q.question, q.type, q.category, q.correct_query
            FROM quest_questions qq
            JOIN questions q ON qq.question_id = q.id
            WHERE qq.quest_id = %s
            ORDER BY qq.sequence;
        """, (quest_id,))

        question_rows = cur.fetchall()

        for row in question_rows:
            question_id, question_text, q_type, category, correct_query = row

            # Fetch hints from `question_hints` table
            cur.execute("""
                SELECT hint_text 
                FROM question_hints 
                WHERE question_id = %s 
                ORDER BY hint_order;
            """, (question_id,))
            hints = [row[0] for row in cur.fetchall()]

            # Fetch relevant table schema
            cur.execute("""
                SELECT column_name, data_type 
                FROM information_schema.columns 
                WHERE table_name = %s;
            """, (category.lower() + "_matches",))  # Assuming table names follow a pattern

            columns = [{"name": col[0], "type": col[1]} for col in cur.fetchall()]

            # Fetch sample data and ensure time/date serialization
            cur.execute(f"SELECT * FROM {category.lower()}_matches LIMIT 3;")
            sample_data = [[serialize_value(value) for value in row] for row in cur.fetchall()]  # ✅ Convert TIME values

            question_data = {
                "problem": {
                    "id": question_id,
                    "question": question_text,
                    "type": q_type,
                    "category": category,
                    "hints": hints
                },
                "tables": {
                    category.lower() + "_matches": {
                        "columns": columns,
                        "sample_data": sample_data
                    }
                }
            }

            quest_data["questions"].append(question_data)

        cur.close()
        conn.close()

        return jsonify(quest_data), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/quests/<int:quest_id>/next-question", methods=["GET"])
@jwt_required()
def get_next_question(quest_id):
    """Retrieve the next unanswered question for the user in a quest."""
    user_id = get_jwt_identity()

    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # Find the next unanswered question for the user
        cur.execute("""
            SELECT q.id, q.question, q.type, q.category
            FROM quest_questions qq
            JOIN questions q ON qq.question_id = q.id
            WHERE qq.quest_id = %s
            AND q.id NOT IN (
                SELECT question_id FROM user_answers WHERE user_id = %s
            )
            ORDER BY qq.sequence
            LIMIT 1;
        """, (quest_id, user_id))

        question = cur.fetchone()
        if not question:
            return jsonify({"message": "No more questions left in this quest"}), 200

        cur.close()
        conn.close()
        return jsonify({"id": question[0], "question": question[1], "type": question[2], "category": question[3]}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ✅ 4. Submit an answer for a quest question
@app.route("/quests/<int:quest_id>/submit-answer", methods=["POST"])
@jwt_required()
def submit_quest_answer(quest_id):
    """Submit an answer for a quest question and track progress."""
    user_id = get_jwt_identity()
    data = request.get_json()
    question_id = data.get("question_id")
    user_query = data.get("user_query")

    if not question_id or not user_query:
        return jsonify({"error": "Question ID and SQL query are required"}), 400

    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # Fetch correct answer
        cur.execute("SELECT correct_query FROM questions WHERE id = %s;", (question_id,))
        correct_query = cur.fetchone()
        if not correct_query:
            return jsonify({"error": "Invalid question ID"}), 400
        correct_query = correct_query[0]

        # Execute and compare results
        cur.execute(correct_query)
        correct_result = cur.fetchall()

        try:
            cur.execute(user_query)
            user_result = cur.fetchall()
        except Exception as e:
            return jsonify({"error": "Invalid SQL query", "details": str(e)}), 400

        is_correct = user_result == correct_result

        # Store the answer
        cur.execute("""
            INSERT INTO user_answers (user_id, question_id, user_query, is_correct)
            VALUES (%s, %s, %s, %s);
        """, (user_id, question_id, user_query, is_correct))

        # Update progress
        if is_correct:
            cur.execute("""
                UPDATE user_quests 
                SET questions_completed = questions_completed + 1, last_updated = NOW()
                WHERE user_id = %s AND quest_id = %s;
            """, (user_id, quest_id))

            # Check if the quest is completed
            cur.execute("""
                SELECT COUNT(*) FROM quest_questions WHERE quest_id = %s;
            """, (quest_id,))
            total_questions = cur.fetchone()[0]

            cur.execute("""
                SELECT questions_completed FROM user_quests WHERE user_id = %s AND quest_id = %s;
            """, (user_id, quest_id))
            user_progress = cur.fetchone()[0]

            if user_progress >= total_questions:
                cur.execute("""
                    UPDATE user_quests SET completed = TRUE WHERE user_id = %s AND quest_id = %s;
                """, (user_id, quest_id))

        conn.commit()
        cur.close()
        conn.close()

        return jsonify({"message": "Answer submitted successfully", "is_correct": is_correct}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ✅ 5. Fetch quest progress
@app.route("/quests/<int:quest_id>/progress", methods=["GET"])
@jwt_required()
def get_quest_progress(quest_id):
    """Retrieve the user's progress in a quest."""
    user_id = get_jwt_identity()

    try:
        conn = get_db_connection()
        cur = conn.cursor()

        cur.execute("""
            SELECT questions_completed, completed FROM user_quests WHERE user_id = %s AND quest_id = %s;
        """, (user_id, quest_id))
        progress = cur.fetchone()

        cur.close()
        conn.close()

        if not progress:
            return jsonify({"message": "No progress found"}), 404

        return jsonify({"questions_completed": progress[0], "completed": progress[1]}), 200

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


def convert_time_values(rows):
    """Convert TIME objects to string format (HH:MM:SS) in query results."""
    return [
        [value.strftime("%H:%M:%S") if isinstance(value, datetime.time) else value for value in row]
        for row in rows
    ]

@app.route("/submit-answer", methods=["POST"])
@jwt_required()
def submit_answer():
    csrf_token_cookie = request.cookies.get("csrf_token")
    csrf_token_header = request.headers.get("X-CSRF-Token")

    if not csrf_token_cookie or not csrf_token_header or csrf_token_cookie != csrf_token_header:
        return jsonify({"error": "CSRF token mismatch"}), 403

    data = request.get_json()
    question_id = data.get("question_id")
    user_query = data.get("user_query")
    is_submit = data.get("is_submit", False)
    xp_spent = data.get("xp_spent",0)
    if not is_safe_query(user_query):
        return jsonify({"error": "Unsafe SQL query detected!"}), 400

    if not question_id or not user_query:
        return jsonify({"error": "Question ID and SQL query are required"}), 400

    user_id = None
    if is_submit:
        try:
            user_id = get_jwt_identity()
            if not user_id:
                return jsonify({"error": "Unauthorized"}), 401
        except Exception as e:
            return jsonify({"error": "JWT Invalid", "details": str(e)}), 401

    conn = None  
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # ✅ Fetch correct query from DB
        cur.execute("SELECT correct_query FROM questions WHERE id = %s;", (question_id,))
        correct_query = cur.fetchone()
        if not correct_query:
            return jsonify({"error": "Invalid question ID"}), 400
        correct_query = correct_query[0]

        # ✅ Execute correct query & measure time
        start_time = timer.time()
        cur.execute(correct_query)
        correct_result = cur.fetchall()
        correct_execution_time = round((timer.time() - start_time) * 1000, 2)  # ✅ Convert to ms

        # ✅ Execute user query & measure time
        try:
            start_time = timer.time()
            cur.execute(user_query)
            user_result = cur.fetchall()
            user_execution_time = round((timer.time() - start_time) * 1000, 2)  # ✅ Convert to ms
        except Exception as e:
            return jsonify({
                "error": "Invalid SQL query",
                "details": str(e),
                "user_query_result": None,
                "correct_query_result": convert_time_values(correct_result),
                "user_execution_time": None,
                "correct_execution_time": correct_execution_time
            }), 400

        # ✅ Compare results
        is_correct = user_result == correct_result

        xp_award = 0
        is_repeat = False

        if is_submit and user_id:
            # ✅ Check if user has already solved this problem correctly
            cur.execute("""
                SELECT COUNT(*) FROM user_answers 
                WHERE user_id = %s AND question_id = %s AND is_correct = TRUE;
            """, (user_id, question_id))
            correct_count = cur.fetchone()[0]
            is_repeat = correct_count > 0

            # ✅ Award XP only for first correct submission
            if is_correct and not is_repeat:
                cur.execute("SELECT type FROM questions WHERE id = %s;", (question_id,))
                question_type_row = cur.fetchone()
                if question_type_row:
                    question_type = question_type_row[0].lower()
                    xp_award = {"easy": 50, "medium": 100, "hard": 200}.get(question_type, 0)

            # ✅ Always store the submission
            cur.execute("""
                INSERT INTO user_answers (user_id, question_id, user_query, is_correct, execution_time)
                VALUES (%s, %s, %s, %s, %s)
            """, (user_id, question_id, user_query, is_correct, user_execution_time))

            # ✅ Update user XP if earned
            if is_correct and xp_award > 0:
                cur.execute("UPDATE users SET xp = xp + %s WHERE id = %s;", (xp_award-xp_spent, user_id))

            conn.commit()

        return jsonify({
            "message": "Query executed successfully" if not is_submit else "Answer submitted successfully",
            "is_correct": is_correct,
            "user_query_result": convert_time_values(user_result),
            "correct_query_result": convert_time_values(correct_result),
            "user_execution_time": user_execution_time,
            "correct_execution_time": correct_execution_time,
            "xp_award": xp_award-xp_spent,
            "is_repeat": is_repeat
        }), 201

    except Exception as e:
        return jsonify({"error": str(e)}), 500

    finally:
        if conn:
            conn.close()  # ✅ Ensure DB connection is always closed


def convert_time_values(rows):
    """Convert TIME objects to string format (HH:MM:SS) in query results."""
    return [
        [value.strftime("%H:%M:%S") if isinstance(value, datetime.time) else value for value in row]
        for row in rows
    ]


@app.route("/run-answer", methods=["POST"])
def run_answer():
    user_id = ""

    data = request.get_json()
    question_id = data.get("question_id")
    user_query = data.get("user_query")
    is_submit = data.get("is_submit", False)

    if not question_id or not user_query:
        return jsonify({"error": "Question ID and SQL query are required"}), 400

    if not is_safe_query(user_query):
        return jsonify({"error": "Unsafe SQL query detected!"}), 400

    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # ✅ Fetch the correct query
        cur.execute("SELECT correct_query FROM questions WHERE id = %s;", (question_id,))
        correct_query = cur.fetchone()
        if not correct_query:
            return jsonify({"error": "Invalid question ID"}), 400
        correct_query = correct_query[0]

        # ✅ Execute Correct Query & Measure Execution Time
        start_time = timer.time()
        cur.execute(correct_query)
        correct_result = cur.fetchall()
        correct_execution_time = round((timer.time() - start_time) * 1000, 2)  # ✅ Convert to ms

        # ✅ Convert TIME objects to string format in correct result
        correct_result = convert_time_values(correct_result)

        # ✅ Execute User Query & Measure Execution Time
        try:
            start_time = timer.time()
            cur.execute(user_query)
            user_result = cur.fetchall()
            user_execution_time = round((timer.time() - start_time) * 1000, 2)  # ✅ Convert to ms

            # ✅ Convert TIME objects to string format in user result
            user_result = convert_time_values(user_result)

        except Exception as e:
            return jsonify({
                "error": "Invalid SQL query",
                "details": str(e),
                "user_query_result": None,
                "correct_query_result": correct_result,
                "user_execution_time": None,
                "correct_execution_time": correct_execution_time
            }), 400

        # ✅ Compare results
        is_correct = user_result == correct_result

        # ✅ Store answer if it's a submission
        if is_submit:
            cur.execute("""
                INSERT INTO user_answers (user_id, question_id, user_query, is_correct, execution_time)
                VALUES (%s, %s, %s, %s, %s)
            """, (user_id, question_id, user_query, is_correct, user_execution_time))
            conn.commit()

        cur.close()
        conn.close()

        return jsonify({
            "message": "Query executed successfully" if not is_submit else "Answer submitted successfully",
            "is_correct": is_correct,
            "user_query_result": user_result,
            "correct_query_result": correct_result,
            "user_execution_time": user_execution_time,
            "correct_execution_time": correct_execution_time
        }), 201

    except Exception as e:
        return jsonify({"error": str(e)}), 500




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
    

@app.route("/leaderboard", methods=["GET"])
@jwt_required()
def get_leaderboard():
    user_id = get_jwt_identity()

    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # Fetch top 10 users by XP
        cur.execute("""
            SELECT username, xp FROM users 
            ORDER BY xp DESC 
            LIMIT 10;
        """)
        top_users = cur.fetchall()

        # Fetch logged-in user's rank if not in top 10
        cur.execute("""
            SELECT username, xp, 
            RANK() OVER (ORDER BY xp DESC) AS rank
            FROM users WHERE id = %s;
        """, (user_id,))
        user_rank = cur.fetchone()

        cur.close()
        conn.close()

        # Format response
        return jsonify({
            "leaderboard": [{"username": user[0], "xp": user[1]} for user in top_users],
            "user_rank": {"username": user_rank[0], "xp": user_rank[1], "rank": user_rank[2]} if user_rank else None
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500



@app.route("/google-login", methods=["POST"])
def google_login():
    # Get the credential from the request
    credential = request.json.get("credential")
    if not credential:
        return jsonify({"error": "Credential is required"}), 400

    try:
        # Specify the CLIENT_ID of the app that accesses the backend
        CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")

        # Verify the token
        idinfo = id_token.verify_oauth2_token(credential, google_requests.Request(), CLIENT_ID)

        # ID token is valid. Get the user's Google Account ID from the decoded token.
        user_id = idinfo['sub']
        email = idinfo.get('email')
        name = idinfo.get('name')

        # Here, you can check if the user exists in your database and create a new user if not
        # For example:
        conn = get_db_connection()
        cur = conn.cursor()

        # Check if user already exists
        cur.execute("SELECT id FROM users WHERE email = %s;", (email,))
        user = cur.fetchone()

        if not user:
            # Create a new user
            placeholder_password = "GOOGLE_LOGIN"
            cur.execute(
                "INSERT INTO users (username, email, password_hash) VALUES (%s, %s, %s) RETURNING id;",
                (name, email, placeholder_password)
            )
            user_id = cur.fetchone()[0]
            conn.commit()
        else:
            user_id = user[0]

        cur.close()
        conn.close()
        access_token = create_access_token(identity=str(user_id))
        refresh_token = create_refresh_token(identity=str(user_id))
        csrf_token = generate_csrf_token()
        response = make_response(jsonify({"message": "Login successful","user_id":user_id}))
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

    except ValueError as e:
        # Invalid token
        return jsonify({"error": "Invalid token"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/challenges", methods=["GET"])
@jwt_required(optional=True)
def get_challenges():
    user_id = get_jwt_identity()
    solved_question_ids = []
    
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # Check if the user is premium
        has_premium = False
        if user_id:
            cur.execute("SELECT is_premium FROM users WHERE id = %s;", (user_id,))
            premium_status = cur.fetchone()
            has_premium = premium_status[0] if premium_status else False

        # Get the category parameter from the query string (if provided)
        category = request.args.get("category")

        if user_id is None:
            # If user is not logged in, fetch only easy questions with submission count
            cur.execute("""
                SELECT q.id, q.question, q.type, q.category, COUNT(ua.id) AS submissions
                FROM questions q
                LEFT JOIN user_answers ua ON q.id = ua.question_id
                WHERE q.type = 'easy'
                GROUP BY q.id;
            """)
            challenges = cur.fetchall()
        else:
            if category == "popular":
                # Fetch the most popular questions
                challenges = get_most_popular_questions(cur)
            else:
                if category:
                    # Filter challenges by the provided category
                    cur.execute("""
                        SELECT q.id, q.question, q.type, q.category, COUNT(ua.id) AS submissions
                        FROM questions q
                        LEFT JOIN user_answers ua ON q.id = ua.question_id
                        WHERE q.category = %s
                        GROUP BY q.id;
                    """, (category,))
                else:
                    cur.execute("""
                        SELECT q.id, q.question, q.type, q.category, COUNT(ua.id) AS submissions
                        FROM questions q
                        LEFT JOIN user_answers ua ON q.id = ua.question_id
                        GROUP BY q.id;
                    """)
                challenges = cur.fetchall()

        if user_id is not None:
            # Fetch the list of question IDs that the user has solved
            cur.execute("""
                SELECT question_id FROM user_answers 
                WHERE user_id = %s AND is_correct = true;
            """, (user_id,))
            solved_questions = cur.fetchall()

            # Extract question IDs from the result
            solved_question_ids = [question[0] for question in solved_questions]
        
        cur.close()
        conn.close()

        challenge_list = [
            {"id": q[0], "question": q[1], "type": q[2], "category": q[3], "submissions": q[4]} for q in challenges
        ]
        
        return jsonify({"challenges": challenge_list, "solved_question_ids": solved_question_ids, "user_premium_status": has_premium}), 200

    except Exception as e:
        # Log the error for debugging
        print(f"Error occurred: {str(e)}")
        return jsonify({"error": "An error occurred while processing your request.", "details": str(e)}), 500

# @app.route("/challenges", methods=["GET"])
# @jwt_required(optional=True)
# def get_challenges():
#     user_id = get_jwt_identity()
#     solved_question_ids = []
    
#     try:
#         conn = get_db_connection()
#         cur = conn.cursor()

#         # Check if the user is premium
#         has_premium = False
#         if user_id:
#             cur.execute("SELECT is_premium FROM users WHERE id = %s;", (user_id,))
#             premium_status = cur.fetchone()
#             has_premium = premium_status[0] if premium_status else False

#         # Get the category parameter from the query string (if provided)
#         category = request.args.get("category")

#         if category == "popular":
#             # Fetch the most popular questions
#             challenges = get_most_popular_questions(cur)
#         else:
#             if category:
#                 # Filter challenges by the provided category
#                 cur.execute("""
#                     SELECT q.id, q.question, q.type,q.category, COUNT(ua.id) AS submissions
#                     FROM questions q
#                     LEFT JOIN user_answers ua ON q.id = ua.question_id
#                     WHERE q.category = %s
#                     GROUP BY q.id;
#                 """, (category,))
#             else:
#                 cur.execute("""
#                     SELECT q.id, q.question, q.type, q.category, COUNT(ua.id) AS submissions
#                     FROM questions q
#                     LEFT JOIN user_answers ua ON q.id = ua.question_id
#                     GROUP BY q.id;
#                 """)
#             challenges = cur.fetchall()

#         if user_id is not None:
#             # Fetch the list of question IDs that the user has solved
#             cur.execute("""
#                 SELECT question_id FROM user_answers 
#                 WHERE user_id = %s AND is_correct = true;
#             """, (user_id,))
#             solved_questions = cur.fetchall()

#             # Extract question IDs from the result
#             solved_question_ids = [question[0] for question in solved_questions]
        
#         cur.close()
#         conn.close()

#         challenge_list = [
#             {"id": q[0], "question": q[1], "type": q[2], "submissions": q[4], "category":q[3]} for q in challenges
#         ]
        
#         return jsonify({"challenges": challenge_list, "solved_question_ids": solved_question_ids, "user_premium_status": True}), 200

#     except Exception as e:
#         return jsonify({"error": str(e)}), 500


def get_most_popular_questions(cur):
    """
    Fetches the 6 most solved and 4 least solved questions.
    """
    # Fetch the 6 most solved questions
    cur.execute("""
        SELECT q.id, q.question, q.type, COUNT(ua.id) AS submissions
        FROM questions q
        LEFT JOIN user_answers ua ON q.id = ua.question_id
        GROUP BY q.id
        ORDER BY submissions DESC
        LIMIT 6;
    """)
    most_solved = cur.fetchall()

    # Fetch the 4 least solved questions
    cur.execute("""
        SELECT q.id, q.question, q.type, COUNT(ua.id) AS submissions
        FROM questions q
        LEFT JOIN user_answers ua ON q.id = ua.question_id
        GROUP BY q.id
        ORDER BY submissions ASC
        LIMIT 4;
    """)
    least_solved = cur.fetchall()

    return most_solved + least_solved  # Combine results


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


@app.route("/discussion", methods=["POST"])
@jwt_required()
def create_comment():
    data = request.get_json()
    user_id = get_jwt_identity()
    question_id = data.get("question_id")
    parent_id = data.get("parent_id", None)  # Optional for replies
    content = data.get("content")

    if not question_id or not content:
        return jsonify({"error": "Question ID and content are required"}), 400

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
        INSERT INTO discussions (user_id, question_id, parent_id, content)
        VALUES (%s, %s, %s, %s) RETURNING id, created_at;
    """, (user_id, question_id, parent_id, content))
    comment = cur.fetchone()

    conn.commit()
    cur.close()
    conn.close()

    return jsonify({
        "message": "Comment added successfully",
        "comment_id": comment[0],
        "created_at": comment[1]
    }), 201

@app.route("/discussion/<int:question_id>", methods=["GET"])
def get_discussion(question_id):
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT d.id, d.user_id, u.username, d.content, d.parent_id, d.created_at, 
               (SELECT COUNT(*) FROM discussion_likes WHERE discussion_id = d.id) AS likes
        FROM discussions d
        JOIN users u ON d.user_id = u.id
        WHERE d.question_id = %s
        ORDER BY d.created_at ASC;
    """, (question_id,))
    
    comments = cur.fetchall()
    conn.close()

    # ✅ Organize comments into a nested structure
    comment_map = {row[0]: {
        "id": row[0],
        "user_id": row[1],
        "username": row[2],
        "content": row[3],
        "parent_id": row[4],
        "created_at": row[5],
        "likes": row[6],
        "replies": []
    } for row in comments}

    discussion = []
    for comment in comment_map.values():
        if comment["parent_id"]:
            comment_map[comment["parent_id"]]["replies"].append(comment)
        else:
            discussion.append(comment)

    return jsonify(discussion)

@app.route("/discussion/like/<int:discussion_id>", methods=["POST"])
@jwt_required()
def like_comment(discussion_id):
    user_id = get_jwt_identity()

    conn = get_db_connection()
    cur = conn.cursor()

    try:
        # ✅ Check if user already liked the comment
        cur.execute("SELECT id FROM discussion_likes WHERE user_id = %s AND discussion_id = %s;", 
                    (user_id, discussion_id))
        existing_like = cur.fetchone()

        if existing_like:
            cur.execute("DELETE FROM discussion_likes WHERE id = %s;", (existing_like[0],))
            message = "Like removed"
        else:
            cur.execute("INSERT INTO discussion_likes (user_id, discussion_id) VALUES (%s, %s);",
                        (user_id, discussion_id))
            message = "Liked successfully"

        conn.commit()
        return jsonify({"message": message})

    except Exception as e:
        return jsonify({"error": str(e)}), 500

    finally:
        cur.close()
        conn.close()

@app.route("/discussion/edit/<int:discussion_id>", methods=["PUT"])
@jwt_required()
def edit_comment(discussion_id):
    user_id = get_jwt_identity()
    data = request.get_json()
    new_content = data.get("content")

    if not new_content:
        return jsonify({"error": "Content cannot be empty"}), 400

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
        UPDATE discussions SET content = %s, updated_at = NOW()
        WHERE id = %s AND user_id = %s;
    """, (new_content, discussion_id, user_id))

    if cur.rowcount == 0:
        return jsonify({"error": "You can only edit your own comments"}), 403

    conn.commit()
    cur.close()
    conn.close()

    return jsonify({"message": "Comment updated successfully"})


@app.route("/discussion/delete/<int:discussion_id>", methods=["DELETE"])
@jwt_required()
def delete_comment(discussion_id):
    user_id = get_jwt_identity()

    conn = get_db_connection()
    cur = conn.cursor()

    # ✅ Only allow users to delete their own comments
    cur.execute("""
        DELETE FROM discussions WHERE id = %s AND user_id = %s;
    """, (discussion_id, user_id))

    if cur.rowcount == 0:
        return jsonify({"error": "You can only delete your own comments"}), 403

    conn.commit()
    cur.close()
    conn.close()

    return jsonify({"message": "Comment deleted successfully"})


@app.route("/submit-test-answer", methods=["POST"])
def submit_test_answer():
    """
    Handles individual question submissions during the test.
    Stores each attempt in the database.
    """
    data = request.get_json()
    test_session_id = data.get("test_session_id")
    question_id = data.get("question_id")
    user_query = data.get("user_query")

    if not all([test_session_id, question_id, user_query]):
        return jsonify({"error": "Missing required fields"}), 400

    if not is_safe_query(user_query):
        return jsonify({"error": "Unsafe SQL query detected!"}), 400

    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # Verify test session is active
        cur.execute("""
            SELECT status FROM test_sessions 
            WHERE id = %s AND status = 'in_progress';
        """, (test_session_id,))
        
        if not cur.fetchone():
            return jsonify({"error": "Invalid or completed test session"}), 400

        # Execute queries and compare results
        start_time = timer.time()
        
        # Get correct query
        cur.execute("SELECT correct_query FROM questions WHERE id = %s;", (question_id,))
        correct_query = cur.fetchone()[0]

        # Execute correct query & measure time
        cur.execute(correct_query)
        correct_result = cur.fetchall()
        correct_execution_time = round((timer.time() - start_time) * 1000, 2)

        # Execute user query & measure time
        try:
            start_time = timer.time()
            cur.execute(user_query)
            user_result = cur.fetchall()
            user_execution_time = round((timer.time() - start_time) * 1000, 2)
        except Exception as e:
            return jsonify({
                "error": "Invalid SQL query",
                "details": str(e),
                "user_result": None,
                "correct_result": correct_result,
                "user_execution_time": None,
                "correct_execution_time": correct_execution_time
            }), 400

        # Compare results
        is_correct = user_result == correct_result

        # Store the attempt
        cur.execute("""
            INSERT INTO test_attempts 
            (test_session_id, question_id, user_query, is_correct, execution_time)
            VALUES (%s, %s, %s, %s, %s)
            RETURNING id;
        """, (test_session_id, question_id, user_query, is_correct, user_execution_time))
        conn.commit()

        return jsonify({
            "is_correct": is_correct,
            "user_result": user_result,
            "correct_result": correct_result,
            "user_execution_time": user_execution_time,
            "correct_execution_time": correct_execution_time
        }), 200

    except Exception as e:
        print("Error in submit_test_answer:", str(e))
        return jsonify({"error": "Internal server error"}), 500
    finally:
        if conn:
            conn.close()

# Required SQL tables (if not already created):
"""
CREATE TABLE test_sessions (
    id UUID PRIMARY KEY,
    user_id UUID,  -- nullable for anonymous users
    start_time TIMESTAMP DEFAULT NOW(),
    end_time TIMESTAMP,
    score INTEGER,
    badge VARCHAR(50),
    status VARCHAR(20) DEFAULT 'in_progress'  -- 'in_progress' or 'completed'
);

CREATE TABLE test_attempts (
    id SERIAL PRIMARY KEY,
    test_session_id UUID REFERENCES test_sessions(id),
    question_id INTEGER REFERENCES questions(id),
    user_query TEXT,
    is_correct BOOLEAN,
    execution_time FLOAT,
    attempted_at TIMESTAMP DEFAULT NOW()
);
"""

# Run Flask Server
if __name__ == "__main__":
    app.run(debug=True)

@app.route("/claim-test/<test_session_id>", methods=["POST"])
@jwt_required()  # Requires authentication
def claim_test(test_session_id):
    """
    Allows a logged-in user to claim a test session that was started anonymously.
    If the test session is already completed, return the session details.
    If the status is 'pending-claim', allow the user to claim it.
    """
    user_id = get_jwt_identity()  # Get the logged-in user's ID from the JWT

    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # Check if test session exists
        cur.execute("""
            SELECT status, user_id 
            FROM test_sessions 
            WHERE id = %s;
        """, (test_session_id,))
        
        test_session = cur.fetchone()
        
        if not test_session:
            return jsonify({"error": "Test session not found"}), 404

        session_status, existing_user_id = test_session
        
        # Ensure user_id is an integer for comparison
        if isinstance(user_id, str):
            user_id = int(user_id)  # Convert to integer if it's a string

        # If the session is already completed
        if session_status == 'completed':
            if existing_user_id == user_id:
                return jsonify({
                    "message": "Test session has already been completed.",
                    "test_session_id": test_session_id,
                    "user_id": existing_user_id
                }), 200
            else:
                return jsonify({
                    "error": "This test session was completed by another user.",
                    "existing_user_id": existing_user_id,
                    "user_id": user_id
                }), 403

        # If the session is pending-claim, allow the user to claim it
        if session_status == 'pending-claim':
            cur.execute("""
                UPDATE test_sessions 
                SET user_id = %s, status = 'completed'  -- Optionally mark as completed
                WHERE id = %s
                RETURNING id;
            """, (user_id, test_session_id))
            
            if cur.fetchone():
                conn.commit()
                return jsonify({
                    "message": "Test session claimed successfully",
                    "test_session_id": test_session_id
                }), 200
            else:
                return jsonify({"error": "Failed to claim test session"}), 400

        # If the session is unclaimed, claim it
        if existing_user_id is None:
            cur.execute("""
                UPDATE test_sessions 
                SET user_id = %s 
                WHERE id = %s
                RETURNING id;
            """, (user_id, test_session_id))
            
            if cur.fetchone():
                conn.commit()
                return jsonify({
                    "message": "Test session claimed successfully",
                    "test_session_id": test_session_id
                }), 200
            else:
                return jsonify({"error": "Failed to claim test session"}), 400
        else:
            return jsonify({"error": "Test session has already been claimed."}), 400

    except Exception as e:
        print("Error in claim_test:", str(e))
        return jsonify({"error": "Internal server error"}), 500
    finally:
        if conn:
            conn.close()



@app.route("/test-report/<test_session_id>", methods=["GET"])
@jwt_required()  # Requires authentication
def get_test_report(test_session_id):
    """
    Fetches complete test report for a logged-in user.
    Only shows reports for tests associated with the requesting user.
    For premium users, the report includes detailed per-question data.
    For free users, only high-level summary and limited per-question details are shown.
    """
    user_id = get_jwt_identity()

    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # First, fetch the test session details and verify ownership
        cur.execute("""
            SELECT user_id, score, badge, start_time, end_time 
            FROM test_sessions 
            WHERE id = %s AND status = 'completed';
        """, (test_session_id,))
        
        test_session = cur.fetchone()
        if not test_session:
            return jsonify({"error": "Test session not found"}), 404
            
        session_user_id = test_session[0]
        if str(session_user_id) != str(user_id):
            return jsonify({"error": "Unauthorized access to test report"}), 403

        # Check if the user is premium
        cur.execute("SELECT is_premium FROM users WHERE id = %s;", (user_id,))
        premium_row = cur.fetchone()
        is_premium = premium_row[0] if premium_row else False

        # Get all attempts with question details
        cur.execute("""
            SELECT 
                q.id,
                q.question,
                q.type,
                q.category,
                q.correct_query,
                ta.user_query,
                ta.is_correct,
                ta.execution_time,
                ta.attempted_at
            FROM test_attempts ta
            JOIN questions q ON ta.question_id = q.id
            WHERE ta.test_session_id = %s
            ORDER BY ta.attempted_at;
        """, (test_session_id,))
        
        attempts = cur.fetchall()

        # Calculate overall statistics
        total_questions = len(attempts)
        correct_answers = sum(1 for attempt in attempts if attempt[6])
        accuracy = round((correct_answers / total_questions * 100), 2) if total_questions > 0 else 0

        question_details = []
        for attempt in attempts:
            # Premium users see all details
            if is_premium:
                required_tables = extract_table_names(attempt[4])  # correct_query
                table_data = extract_table_data(required_tables)
                question_detail = {
                    "question_id": attempt[0],
                    "question_text": attempt[1],
                    "type": attempt[2],
                    "category": attempt[3],
                    "correct_query": attempt[4],
                    "user_query": attempt[5],
                    "is_correct": attempt[6],
                    "execution_time": attempt[7],
                    "attempted_at": attempt[8],
                    "table_schemas": table_data
                }
            else:
                # Free users get limited details (hide sensitive details)
                question_detail = {
                    "question_id": attempt[0],
                    "question_text": attempt[1],
                    "type": attempt[2],
                    "category": attempt[3],
                    "is_correct": attempt[6],
                    "attempted_at": attempt[8]
                }
            question_details.append(question_detail)

        # Build a performance summary
        performance_summary = {
            "easy_questions": sum(1 for q in question_details if q["type"] == "easy"),
            "medium_questions": sum(1 for q in question_details if q["type"] == "medium"),
            "hard_questions": sum(1 for q in question_details if q["type"] == "hard"),
            "easy_correct": sum(1 for q in question_details if q["type"] == "easy" and q.get("is_correct")),
            "medium_correct": sum(1 for q in question_details if q["type"] == "medium" and q.get("is_correct")),
            "hard_correct": sum(1 for q in question_details if q["type"] == "hard" and q.get("is_correct"))
        }
        # Include average execution time only for premium users
        if is_premium and total_questions > 0:
            avg_exec_time = round(sum(q["execution_time"] for q in question_details if q.get("execution_time")) / total_questions, 2)
            performance_summary["avg_execution_time"] = avg_exec_time

        test_summary = {
            "test_session_id": test_session_id,
            "score": test_session[1],
            "badge": test_session[2],
            "start_time": test_session[3],
            "end_time": test_session[4],
            "total_questions": total_questions,
            "correct_answers": correct_answers,
            "accuracy": accuracy,
            "completion_time": str(test_session[4] - test_session[3]) if test_session[4] else None
        }

        response_data = {
            "test_summary": test_summary,
            "question_details": question_details,
            "performance_summary": performance_summary,
            "is_premium": is_premium  # Optional flag to help the frontend adjust display
        }
        return jsonify(response_data), 200

    except Exception as e:
        print("Error in get_test_report:", str(e))
        return jsonify({"error": "Internal server error"}), 500
    finally:
        if conn:
            conn.close()

# @app.route("/test-report/<test_session_id>", methods=["GET"])
# @jwt_required()  # Requires authentication
# def get_test_report(test_session_id):
#     """
#     Fetches complete test report for a logged-in user.
#     Only shows reports for tests associated with the requesting user.
#     """
#     user_id = get_jwt_identity()

#     try:
#         conn = get_db_connection()
#         cur = conn.cursor()

#         # First verify this test belongs to the requesting user
#         cur.execute("""
#             SELECT user_id, score, badge, start_time, end_time 
#             FROM test_sessions 
#             WHERE id = %s AND status = 'completed';
#         """, (test_session_id,))
        
#         test_session = cur.fetchone()
        
#         if not test_session:
#             return jsonify({"error": "Test session not found"}), 404
            
#         session_user_id = test_session[0]
#         if str(session_user_id) != str(user_id):
#             return jsonify({"error": "Unauthorized access to test report"}), 403

#         # Get all attempts with question details
#         cur.execute("""
#             SELECT 
#                 q.id,
#                 q.question,
#                 q.type,
#                 q.category,
#                 q.correct_query,
#                 ta.user_query,
#                 ta.is_correct,
#                 ta.execution_time,
#                 ta.attempted_at
#             FROM test_attempts ta
#             JOIN questions q ON ta.question_id = q.id
#             WHERE ta.test_session_id = %s
#             ORDER BY ta.attempted_at;
#         """, (test_session_id,))
        
#         attempts = cur.fetchall()

#         # Calculate statistics
#         total_questions = len(attempts)
#         correct_answers = sum(1 for attempt in attempts if attempt[6])  # is_correct
#         accuracy = round((correct_answers / total_questions * 100), 2) if total_questions > 0 else 0
        
#         # Get table schemas for each question
#         question_details = []
#         for attempt in attempts:
#             question_id = attempt[0]
            
#             # Extract tables from correct query
#             required_tables = extract_table_names(attempt[4])  # correct_query
#             table_data = extract_table_data(required_tables)
            
#             question_details.append({
#                 "question_id": question_id,
#                 "question_text": attempt[1],
#                 "type": attempt[2],
#                 "category": attempt[3],
#                 "correct_query": attempt[4],
#                 "user_query": attempt[5],
#                 "is_correct": attempt[6],
#                 "execution_time": attempt[7],
#                 "attempted_at": attempt[8],
#                 "table_schemas": table_data
#             })

#         return jsonify({
#             "test_summary": {
#                 "test_session_id": test_session_id,
#                 "score": test_session[1],  # score
#                 "badge": test_session[2],  # badge
#                 "start_time": test_session[3],
#                 "end_time": test_session[4],
#                 "total_questions": total_questions,
#                 "correct_answers": correct_answers,
#                 "accuracy": accuracy,
#                 "completion_time": str(test_session[4] - test_session[3]) if test_session[4] else None
#             },
#             "question_details": question_details,
#             "performance_summary": {
#                 "easy_questions": sum(1 for q in question_details if q["type"] == "easy"),
#                 "medium_questions": sum(1 for q in question_details if q["type"] == "medium"),
#                 "hard_questions": sum(1 for q in question_details if q["type"] == "hard"),
#                 "easy_correct": sum(1 for q in question_details if q["type"] == "easy" and q["is_correct"]),
#                 "medium_correct": sum(1 for q in question_details if q["type"] == "medium" and q["is_correct"]),
#                 "hard_correct": sum(1 for q in question_details if q["type"] == "hard" and q["is_correct"]),
#                 "avg_execution_time": round(sum(q["execution_time"] for q in question_details) / len(question_details), 2)
#             }
#         }), 200

#     except Exception as e:
#         print("Error in get_test_report:", str(e))
#         return jsonify({"error": "Internal server error"}), 500
#     finally:
#         if conn:
#             conn.close()

@app.route("/report-issue", methods=["POST"])
def report_issue():
    """
    Endpoint to report an issue.
    Expects JSON payload with 'issue_reported' and 'comments'.
    """
    data = request.get_json()

    # Validate input
    issue_reported = data.get("issue_reported")
    comments = data.get("comments")
    user_id = data.get("user_id")
    question_id = data.get("question_id")
    if not issue_reported:
        return jsonify({"error": "Issue reported is required."}), 400

    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # Insert the reported issue into the database
        cur.execute("""
            INSERT INTO user_issues (issue_reported, comments,user_id,question_id) 
            VALUES (%s, %s,%s,%s) 
            RETURNING id;
        """, (issue_reported, comments,user_id,question_id))

        issue_id = cur.fetchone()[0]
        conn.commit()

        return jsonify({
            "message": "Issue reported successfully.",
            "issue_id": issue_id
        }), 201

    except Exception as e:
        print("Error in report_issue:", str(e))
        return jsonify({"error": "Internal server error."}), 500
    finally:
        if conn:
            conn.close()

def verify_signature(raw_body, headers):
    signature_header = headers.get("webhook-signature")
    timestamp = headers.get("webhook-timestamp")
    
    if not signature_header or not timestamp:
        return False

    try:
        provided_signature = signature_header.split(",")[1] if "," in signature_header else signature_header
        computed_signature = hmac.new(
            DODO_SECRET.encode(),
            msg=(timestamp + raw_body).encode(),
            digestmod=hashlib.sha256
        ).digest()

        # Convert both to base64 for comparison
        import base64
        computed_signature_b64 = base64.b64encode(computed_signature).decode()

        return hmac.compare_digest(computed_signature_b64, provided_signature)
    except Exception as e:
        print("❌ Signature verification error:", e)
        return False



@app.route("/sql-premium", methods=["POST"])
def handle_sql_webhook():
    try:
        raw_body = request.data.decode("utf-8")
        headers = request.headers

        webhook_headers = {
            "webhook-id": headers.get("webhook-id", ""),
            "webhook-signature": headers.get("webhook-signature", ""),
            "webhook-timestamp": headers.get("webhook-timestamp", "")
        }

        try:
            wh = Webhook(DODO_SECRET)
            wh.verify(raw_body, webhook_headers)
        except Exception as sig_err:
            print("❌ Invalid webhook signature:", sig_err)
            return jsonify({"error": "Invalid signature"}), 400
        payload = json.loads(raw_body)
        event_type = payload.get("type")
        customer_email = payload.get("data", {}).get("customer", {}).get("email")

        if not customer_email:
            print("❌ Missing email in webhook payload")
            return jsonify({"error": "Missing customer email"}), 400

        if event_type == "payment.succeeded":
            print(f"✅ SQL Payment succeeded for {customer_email}")

            conn = get_db_connection()
            if not conn:
                return jsonify({"error": "Database connection failed"}), 500

            try:
                cur = conn.cursor()
                cur.execute("UPDATE users SET is_premium = TRUE WHERE email = %s", (customer_email,))
                conn.commit()
                cur.close()
                conn.close()
                print(f"🎉 Upgraded {customer_email} to premium in SQL Premier League")
                return jsonify({"success": True}), 200
            except Exception as db_err:
                print("❌ DB Update Error:", db_err)
                return jsonify({"error": "Database update failed"}), 500

        print(f"ℹ️ Unhandled SQL webhook event: {event_type}")
        return jsonify({"received": True}), 200

    except Exception as e:
        print("❌ Webhook Processing Error:", str(e))
        return jsonify({"error": "Internal server error"}), 500
