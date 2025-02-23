import psycopg2
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")

# SQL statements to create necessary tables
MIGRATIONS = [
    """
    CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        email VARCHAR(100) UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS questions (
        id SERIAL PRIMARY KEY,
        question TEXT NOT NULL,
        type VARCHAR(50) NOT NULL,
        correct_query TEXT NOT NULL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS user_answers (
        id SERIAL PRIMARY KEY,
        user_id INT REFERENCES users(id) ON DELETE CASCADE,
        question_id INT REFERENCES questions(id) ON DELETE CASCADE,
        user_query TEXT NOT NULL,
        is_correct BOOLEAN DEFAULT FALSE,
        submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """
]

def apply_migrations():
    """Applies database migrations."""
    try:
        conn = psycopg2.connect(DATABASE_URL)
        cur = conn.cursor()
        
        for query in MIGRATIONS:
            cur.execute(query)
        
        conn.commit()
        cur.close()
        conn.close()
        print("✅ Database migrations applied successfully!")
    except Exception as e:
        print(f"❌ Error applying migrations: {e}")

if __name__ == "__main__":
    apply_migrations()
