import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session, jsonify
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///project.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def inbox():
    """Show all the emails received"""
    userId = session["user_id"]
    usernameDB = db.execute("SELECT username FROM users WHERE id = ?", userId)
    username = usernameDB[0]["username"]
    emails = db.execute("SELECT * FROM emails WHERE recipient = ?", username)
    return render_template("index.html", emails=emails)


@app.route("/compose", methods=["GET", "POST"])
@login_required
def compose():
    """Write an email to someone"""
    if request.method == "GET":
        userId = session["user_id"]
        senderDB = db.execute("SELECT username from users WHERE id = ?", userId)
        sender = senderDB[0]["username"]
        return render_template("compose.html", sender=sender)

    else:
        sender = request.form.get("sender")
        recipient = request.form.get("recipient")
        subject = request.form.get("subject")
        body = request.form.get("body")

        if not sender or not recipient or not subject or not body:
            return apology("No empty fields")

        db.execute(
            "INSERT INTO emails (sender, recipient, subject, body) VALUES (?, ?, ?, ?)",
            sender,
            recipient,
            subject,
            body,
        )

        return redirect("/sent")


@app.route("/sent")
@login_required
def sent():
    """Show sent emails"""
    userId = session["user_id"]
    usernameDB = db.execute("SELECT username FROM users WHERE id = ?", userId)
    username = usernameDB[0]["username"]
    emails = db.execute("SELECT * FROM emails WHERE sender = ?", username)
    return render_template("sent.html", emails=emails)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""
    session.clear()
    if request.method == "POST":
        if not request.form.get("email"):
            return apology("must provide username", 403)
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("email")
        )

        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return apology("invalid username and/or password", 403)

        session["user_id"] = rows[0]["id"]
        return redirect("/")

    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/email", methods=["POST"])
@login_required
def email():
    """View email details"""
    if request.method == "POST":
        emailId = request.form.get("emailId")
        emailDetailDB = db.execute("SELECT * FROM emails WHERE id = ?", emailId)
        emailDetail = emailDetailDB[0]
        return render_template("email.html", emailDetail=emailDetail)


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "GET":
        return render_template("register.html")
    else:
        email = request.form.get("email")
        password = request.form.get("password")
        confirm = request.form.get("confirm")

        if not email or not password or not confirm:
            return apology("No empty fields")
        if password != confirm:
            return apology("Passwords do not match")

        hash = generate_password_hash(password)

        try:
            newUser = db.execute(
                "INSERT INTO users (username, hash) VALUES (?, ?)", email, hash
            )
        except:
            return apology("Username already exists")

        session["user_id"] = newUser

        return redirect("/")


@app.route("/reply", methods=["POST"])
@login_required
def reply():
    """Reply to the email on email detail"""
    if request.method == "POST":
        emailId = request.form.get("emailId")
        emailDetailDB = db.execute("SELECT * FROM emails WHERE id = ?", emailId)
        emailDetail = emailDetailDB[0]
        return render_template("reply.html", emailDetail=emailDetail)
