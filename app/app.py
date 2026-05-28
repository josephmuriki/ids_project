import csv
from flask import send_file
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import random
import sqlite3
from flask import jsonify
from reportlab.platypus import SimpleDocTemplate, Table
from flask import Flask, render_template, request, redirect, session, flash
import sqlite3
import os
import pickle
import numpy as np
import pandas as pd
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "super_secret_key"

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[]
)

DB = "database.db"
MODEL = "model.pkl"

def get_db_connection():

    conn = sqlite3.connect(
        DB,
        timeout=30,
        check_same_thread=False
    )

    conn.execute("PRAGMA journal_mode=WAL")

    return conn

EXPECTED_FEATURES = 78

def fix_input_size(values):
    if len(values) < EXPECTED_FEATURES:
        values += [0.0] * (EXPECTED_FEATURES - len(values))
    elif len(values) > EXPECTED_FEATURES:
        values = values[:EXPECTED_FEATURES]
    return values

# DATABASE 

def init_db():
    conn = get_db_connection()
    c = conn.cursor()

    c.execute("""
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        fullname TEXT,
        email TEXT,
        username TEXT UNIQUE,
        password TEXT,
        role TEXT,
        created_at TEXT
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS detections(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        source TEXT,
        result TEXT,
        score REAL,
        username TEXT
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS activity_logs(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        action TEXT,
        username TEXT
    )
    """)

    conn.commit()

    c.execute("SELECT * FROM users WHERE username='admin'")
    if not c.fetchone():
        c.execute("""
        INSERT INTO users(fullname,email,username,password,role,created_at)
        VALUES(?,?,?,?,?,?)
        """,(
            "System Admin",
            "admin@mail.com",
            "admin",
            generate_password_hash("admin"),
            "admin",
            datetime.now()
        ))
        conn.commit()

    conn.close()

# MODEL 

import joblib
model = joblib.load("../models/ids_model.pkl")

# HYBRID DETECTION 

def signature_check(values):
    try:
        packet_size = float(values[5])  # packet_size column
        if packet_size > 1500:
            return "Signature Attack", 1.0
    except:
        pass
    return None, None

ATTACK_MAP = {
    0: "Normal",
    1: "DoS Hulk",
    2: "PortScan",
    3: "DDoS",
    4: "Botnet",
    5: "FTP Brute Force",
    6: "SSH Brute Force",
    7: "Web Attack",
    8: "Infiltration",
    9: "Heartbleed",
    10: "DoS GoldenEye",
    11: "DoS Slowloris",
    12: "Web Attack SQL Injection",
    13: "Web Attack XSS",
    14: "Bot Attack"
}

def detect(values):
    try:
        # convert to numpy
        values = np.array(values, dtype=float).reshape(1, -1)

        # validate feature size
        if values.shape[1] != EXPECTED_FEATURES:
            return "Invalid Input", 0.0

        # predict
        prediction = model.predict(values)[0]

        # map to label
        label = ATTACK_MAP.get(prediction, "Unknown Attack")

        # confidence
        try:
            proba = model.predict_proba(values)
            confidence = float(np.max(proba))
        except:
            confidence = 1.0

        return label, round(confidence, 4)

    except Exception as e:
        print("MODEL ERROR:", e)
        return "Error", 0.0

def preprocess_row(row):
    processed = []

    for value in row:
        try:
            processed.append(float(value))
        except:
            # Convert strings to numeric using hash
            processed.append(float(abs(hash(str(value))) % 1000))

    return processed

# DATA PREPROCESSING

def log_detection(source, result, score, username):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("""
    INSERT INTO detections(timestamp,source,result,score,username)
    VALUES(?,?,?,?,?)
    """,(datetime.now(),source,result,score,username))
    conn.commit()
    conn.close()

def log_activity(action, username):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("""
    INSERT INTO activity_logs(timestamp,action,username)
    VALUES(?,?,?)
    """,(datetime.now(),action,username))
    conn.commit()
    conn.close()

# AUTH ROUTES

@app.route("/")
def index():
    return redirect("/login")

@app.route("/login", methods=["GET","POST"])
@limiter.limit("5 per minute")
def login():
    if request.method == "POST":
        try:

            username = request.form["username"]
            password = request.form["password"]

            conn = get_db_connection()
            c = conn.cursor()
            c.execute("SELECT * FROM users WHERE username=?",(username,))
            user = c.fetchone()
            conn.close()

            if user and check_password_hash(user[4], password):
                session["user"] = user[3]
                session["role"] = user[5]
                log_activity("Logged in", user[3])
                return redirect("/dashboard")
            else:
                flash("Invalid credentials")

        except Exception:
            flash("Login error")

    return render_template("login.html")

@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "POST":
        try:
            conn = get_db_connection()
            c = conn.cursor()
            c.execute("""
            INSERT INTO users(fullname,email,username,password,role,created_at)
            VALUES(?,?,?,?,?,?)
            """,(
                request.form["fullname"],
                request.form["email"],
                request.form["username"],
                generate_password_hash(request.form["password"]),
                "user",
                datetime.now()
            ))
            conn.commit()
            conn.close()
            return redirect("/login")
        except:
            flash("Username already exists")

    return render_template("register.html")

@app.route("/logout")
def logout():
    log_activity("Logged out", session.get("user"))
    session.clear()
    return redirect("/login")

# DASHBOARD

@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect("/login")

    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM detections")
    total = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM detections WHERE result!='Normal'")
    attacks = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM users")
    users = c.fetchone()[0]
    conn.close()

    return render_template("dashboard.html",
                           total=total,
                           attacks=attacks,
                           users=users,
                           role=session["role"])

# MANUAL PREDICTION 

@app.route("/prediction", methods=["GET","POST"])
def prediction():
    if "user" not in session:
        return redirect("/login")

    result = None

    if request.method == "POST":
        try:
            values = list(map(float, request.form.getlist("values")))
            result, score = detect(values)
            log_detection("manual", result, score, session["user"])
            result = f"{result} | Score: {round(score,4)}"
        except Exception:
            flash("Invalid input values. Please enter numeric values only.")

    return render_template("prediction.html", result=result)

# CSV UPLOAD

@app.route("/upload_csv", methods=["GET","POST"])
def upload_csv():
    if "user" not in session:
        return redirect("/login")

    summary = None

    if request.method == "POST":
        try:
            # FILE VALIDATION 
            if "file" not in request.files:
                flash("No file uploaded")
                return render_template("upload_csv.html", summary=None)

            file = request.files["file"]

            if file.filename == "":
                flash("Please select a CSV file")
                return render_template("upload_csv.html", summary=None)

            if not file.filename.lower().endswith(".csv"):
                flash("Only CSV files are allowed")
                return render_template("upload_csv.html", summary=None)

            # READ CSV 
            df = pd.read_csv(file)

            # DROP LABEL COLUMN
            if "Label" in df.columns:
                df = df.drop(columns=["Label"])

            #  ENSURE NUMERIC DATA
            # Convert all columns to numeric safely
            df = df.apply(pd.to_numeric, errors='coerce')

            # Fill missing values
            df = df.fillna(0)

            # VALIDATE FEATURE SIZE
            EXPECTED_FEATURES = 78  # CICIDS model

            if df.shape[1] != EXPECTED_FEATURES:
                flash(f"Invalid CSV format. Expected {EXPECTED_FEATURES} features, got {df.shape[1]}")
                return render_template("upload_csv.html", summary=None)

            # DETECTION
            normal = anomaly = signature = 0

            for _, row in df.iterrows():
                try:
                    values = row.tolist()

                    result, score = detect(values)

                    log_detection("csv", result, score, session["user"])

                    if result == "Normal":
                        normal += 1
                    elif result == "Anomaly Attack":
                        anomaly += 1
                    else:
                        signature += 1

                except Exception:
                    # If one row fails, log but continue
                    log_detection("csv", "Invalid Input", 0.0, session["user"])

            #  SUMMARY
            summary = {
                "total": len(df),
                "normal": normal,
                "anomaly": anomaly,
                "signature": signature
            }

        except Exception as e:
            print("CSV ERROR:", e)
            flash("Invalid CSV file or corrupted format.")

    return render_template("upload_csv.html", summary=summary)
# INCIDENTS

@app.route("/incidents")
def incidents():
    if "user" not in session:
        return redirect("/login")

    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM detections ORDER BY id DESC")
    data = c.fetchall()
    conn.close()

    return render_template("incidents.html", data=data)

# ADMIN

@app.route("/admin")
def admin():
    if session.get("role") != "admin":
        return redirect("/dashboard")

    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM activity_logs ORDER BY id DESC")
    logs = c.fetchall()
    conn.close()

    return render_template("admin.html", logs=logs)

@app.route("/users")
def users():
    if session.get("role") != "admin":
        return redirect("/dashboard")

    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT id,fullname,email,username,role FROM users")
    users = c.fetchall()
    conn.close()

    return render_template("users.html", users=users)

# USER DELETE

@app.route("/delete_user/<int:user_id>")
def delete_user(user_id):

    if session.get("role") != "admin":
        return redirect("/dashboard")

    try:
        conn = get_db_connection()
        c = conn.cursor()

        c.execute("DELETE FROM users WHERE id=?", (user_id,))
        conn.commit()
        conn.close()

        log_activity("Deleted user ID "+str(user_id), session["user"])

    except Exception:
        flash("Error deleting user")

    return redirect("/users")

# CLEAR LOGS

@app.route("/clear_logs")
def clear_logs():

    if session.get("role")!="admin":
        return redirect("/dashboard")

    try:
        conn = get_db_connection()
        c = conn.cursor()

        c.execute("DELETE FROM activity_logs")

        conn.commit()
        conn.close()

    except Exception:
        flash("Unable to clear logs")

    return redirect("/admin")

# CHART DATA

@app.route("/chart_data")
def chart_data():
    conn = get_db_connection()
    c = conn.cursor()

    # Only consider last 1 minute of activity
    c.execute("""
    SELECT result, COUNT(*) 
    FROM detections 
    WHERE timestamp >= datetime('now', '-1 minute')
    GROUP BY result
    """)

    data = c.fetchall()
    conn.close()

    normal = 0
    attacks = 0

    for row in data:
        if row[0] == "Normal":
            normal = row[1]
        else:
            attacks += row[1]

    return {"normal": normal, "attacks": attacks}

# TOP ATTACKERS
@app.route("/top_attackers")
def top_attackers():

    conn = get_db_connection()
    c = conn.cursor()

    c.execute("""
    SELECT source, COUNT(*) 
    FROM detections
    WHERE result!='Normal'
    GROUP BY source
    ORDER BY COUNT(*) DESC
    LIMIT 5
    """)

    rows = c.fetchall()
    conn.close()

    return {"data": rows}

# EXPORT CSV

@app.route("/export_csv")
def export_csv():

    try:

        conn = get_db_connection()
        c = conn.cursor()

        c.execute("SELECT id,timestamp,source,result,score,username FROM detections")
        rows = c.fetchall()

        conn.close()

        file="incidents.csv"

        with open(file,"w",newline="") as f:
            writer=csv.writer(f)
            writer.writerow(["ID","Timestamp","Source IP","Result","Score","User"])
            writer.writerows(rows)

        return send_file(file,as_attachment=True)

    except Exception:
        flash("CSV export failed")
        return redirect("/incidents")

# EXPORT PDF

@app.route("/export_pdf")
def export_pdf():

    try:

        conn = get_db_connection()
        c = conn.cursor()

        c.execute("SELECT source,result,timestamp FROM detections")
        rows = c.fetchall()

        conn.close()

        file="incidents_report.pdf"

        data=[["Source IP","Result","Time"]]

        for r in rows:
            data.append(list(r))

        pdf=SimpleDocTemplate(file)
        table=Table(data)
        pdf.build([table])

        return send_file(file,as_attachment=True)

    except Exception:
        flash("PDF export failed")
        return redirect("/incidents")

# LIVE ALERTS

@app.route("/live_alerts")
def live_alerts():

    conn = get_db_connection()
    c = conn.cursor()

    c.execute("""
    SELECT result, source, timestamp 
    FROM detections 
    WHERE result!='Normal' 
    ORDER BY id DESC 
    LIMIT 1
    """)
    row = c.fetchone()

    conn.close()

    if row:
        return {"attack": row[0],"ip": row[1],"time": row[2]}

    return {"attack": None}

# NETWORK HEATMAP

@app.route("/network_heatmap")
def network_heatmap():

    conn = get_db_connection()
    c = conn.cursor()

    c.execute("""
    SELECT source, COUNT(*) 
    FROM detections 
    WHERE result!='Normal'
    GROUP BY source
    """)

    rows = c.fetchall()
    conn.close()

    heat = {}

    for r in rows:
        src = r[0]
        count = r[1]

        if src not in heat:
            heat[src] = 0

        heat[src] += count

    return {"data": heat}

@app.route("/attack_map")
def attack_map():

    data = {
        "locations":[
            {"lat":37.77,"lon":-122.41,"country":"USA"},
            {"lat":55.75,"lon":37.61,"country":"Russia"},
            {"lat":39.90,"lon":116.40,"country":"China"},
            {"lat":28.61,"lon":77.20,"country":"India"},
            {"lat":51.50,"lon":-0.12,"country":"UK"}
        ]
    }

    return jsonify(data)

@app.errorhandler(429)
def ratelimit_handler(e):
    return render_template("login.html", error="Too many login attempts. Please wait a minute."), 429

if __name__ == "__main__":
    init_db()
    app.run(debug=True)