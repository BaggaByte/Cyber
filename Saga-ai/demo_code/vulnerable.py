# intentionally_vulnerable_demo.py
# FOR SECURITY TRAINING AND REPORT-TESTING ONLY

from flask import Flask, request, render_template_string
import sqlite3
import pickle
import os

app = Flask(__name__)
app.secret_key = "super-secret-key"  # Hardcoded secret (CWE-798)


# Setup demo DB
def init_db():
    conn = sqlite3.connect("demo.db")
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT
        )
    """)
    cur.execute(
        "INSERT OR IGNORE INTO users VALUES (1, 'admin', 'password123')"
    )
    conn.commit()
    conn.close()


init_db()


# -------------------------
# SQL Injection (CWE-89)
# -------------------------
@app.route("/login")
def login():
    username = request.args.get("username", "")

    conn = sqlite3.connect("demo.db")
    cur = conn.cursor()

    query = f"SELECT * FROM users WHERE username='{username}'"

    try:
        cur.execute(query)
        return {"result": str(cur.fetchall())}
    except Exception as e:
        return {"error": str(e)}
    finally:
        conn.close()


# -------------------------
# Command Injection Pattern (CWE-78)
# -------------------------
@app.route("/files")
def files():
    filename = request.args.get("name", "")

    command = f"dir {filename}" if os.name == "nt" else f"ls {filename}"

    try:
        output = os.popen(command).read()
        return {"output": output}
    except Exception as e:
        return {"error": str(e)}


# -------------------------
# Unsafe eval() (CWE-94)
# -------------------------
@app.route("/calc")
def calc():
    expr = request.args.get("expr", "")

    try:
        result = eval(expr)
        return {"result": str(result)}
    except Exception as e:
        return {"error": str(e)}


# -------------------------
# Path Traversal Pattern (CWE-22)
# -------------------------
@app.route("/read")
def read_file():
    filename = request.args.get("file", "")

    try:
        with open(filename, "r") as f:
            return {"content": f.read()}
    except Exception as e:
        return {"error": str(e)}


# -------------------------
# Server-Side Template Injection Pattern (CWE-1336)
# -------------------------
@app.route("/hello")
def hello():
    name = request.args.get("name", "Guest")
    template = f"<h1>Hello {name}</h1>"

    try:
        return render_template_string(template)
    except Exception as e:
        return {"error": str(e)}


# -------------------------
# Insecure Deserialization Pattern (CWE-502)
# -------------------------
@app.route("/load")
def load():
    data = request.args.get("data", "")

    try:
        obj = pickle.loads(data.encode())
        return {"result": str(obj)}
    except Exception as e:
        return {"error": str(e)}


if __name__ == "__main__":
    app.run(debug=True)