"""Harborline Bank - Demo Banking Portal for Network Security Testing."""

from __future__ import annotations

import time
from pathlib import Path

from flask import Flask, jsonify, redirect, render_template, request, session, url_for

BASE_DIR = Path(__file__).resolve().parent
app = Flask(__name__, template_folder=BASE_DIR / "templates", static_folder=BASE_DIR / "static")
app.config["SECRET_KEY"] = "harborline-bank-demo-key-2026"

TRANSACTIONS = [
    {"id": "TXN9023", "date": "2026-09-25", "desc": "ACH Transfer to AMEX", "amount": -1450.00, "status": "Completed"},
    {"id": "TXN9024", "date": "2026-09-26", "desc": "Direct Deposit - TechCorp", "amount": 4250.00, "status": "Completed"},
    {"id": "TXN9025", "date": "2026-09-26", "desc": "Starbucks Coffee", "amount": -4.50, "status": "Completed"},
    {"id": "TXN9026", "date": "2026-09-27", "desc": "Zelle Transfer - John Doe", "amount": -150.00, "status": "Pending"},
    {"id": "TXN9027", "date": "2026-09-27", "desc": "Amazon Purchase", "amount": -89.99, "status": "Completed"},
    {"id": "TXN9028", "date": "2026-09-27", "desc": "Interest Payment", "amount": 12.34, "status": "Completed"},
]


@app.context_processor
def inject_user():
    return {"current_user": session.get("user", None)}


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        if "@" in email and len(password) > 3:
            session["user"] = email
            return redirect(url_for("dashboard"))
        else:
            error = "Invalid credentials. Please try again."
    return render_template("login.html", error=error)


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        if email:
            session["user"] = email
            return redirect(url_for("dashboard"))
    return render_template("signup.html")


@app.route("/dashboard")
def dashboard():
    if not session.get("user"):
        return redirect(url_for("login"))
    return render_template("dashboard.html", transactions=TRANSACTIONS)


@app.route("/transfer", methods=["GET", "POST"])
def transfer():
    if not session.get("user"):
        return redirect(url_for("login"))
    success = False
    if request.method == "POST":
        success = True
    return render_template("transfer.html", success=success)


@app.route("/policy")
def policy():
    return render_template("policy.html")


@app.route("/search")
def search():
    query = request.args.get("q", "").strip()
    results = [t for t in TRANSACTIONS if query.lower() in t["desc"].lower()] if query else TRANSACTIONS
    return render_template("search.html", query=query, results=results)


@app.route("/upload", methods=["GET", "POST"])
def upload():
    if not session.get("user"):
        return redirect(url_for("login"))
    filename = None
    if request.method == "POST":
        uploaded_file = request.files.get("file")
        filename = uploaded_file.filename if uploaded_file and uploaded_file.filename else "No file selected"
    return render_template("upload.html", filename=filename)


@app.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.get("/health")
def health():
    return jsonify({"status": "operational", "service": "Harborline Bank API"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=True)