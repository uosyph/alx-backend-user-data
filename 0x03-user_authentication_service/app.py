#!/usr/bin/env python3
"""API Routes for Authentication Service"""

from auth import Auth
from flask import Flask, jsonify, request, abort, redirect

app = Flask(__name__)
AUTH = Auth()


@app.route("/", methods=["GET"])
def index() -> str:
    """Base route for authentication service API"""
    return jsonify({"message": "Bienvenue"})


@app.route("/users", methods=["POST"])
def register() -> str:
    """Registers a new user if it does not exist before"""
    try:
        email = request.form["email"]
        password = request.form["password"]
    except KeyError:
        abort(400)

    try:
        user = AUTH.register_user(email, password)
    except ValueError:
        return jsonify({"message": "email already registered"}), 400

    return jsonify({"email": email, "message": "user created"})


@app.route("/sessions", methods=["POST"])
def login() -> str:
    """Logs in a user and returns session ID"""
    try:
        email = request.form["email"]
        password = request.form["password"]
    except KeyError:
        abort(400)

    if not AUTH.valid_login(email, password):
        abort(401)

    session_id = AUTH.create_session(email)
    response = jsonify({"email": email, "message": "logged in"})
    response.set_cookie("session_id", session_id)

    return response


@app.route("/sessions", methods=["DELETE"])
def logout() -> str:
    """Logs out the user if logged in"""
    session_id = request.cookies.get("session_id", None)
    if session_id is None:
        abort(403)

    user = AUTH.get_user_from_session_id(session_id)
    if user is None:
        abort(403)

    AUTH.destroy_session(user.id)

    return redirect("/")


@app.route("/profile", methods=["GET"])
def profile() -> str:
    """return 200 if user exist, otherwise 403."""
    session_id = request.cookies.get("session_id", None)
    if session_id is None:
        abort(403)

    user = AUTH.get_user_from_session_id(session_id)
    if user is None:
        abort(403)

    return jsonify({"email": user.email}), 200


@app.route("/reset_password", methods=["POST"])
def reset_password() -> str:
    """Generates a token if user exists, otherwise return 403."""
    try:
        email = request.form["email"]
    except KeyError:
        abort(403)

    try:
        reset_token = AUTH.get_reset_password_token(email)
    except ValueError:
        abort(403)

    return jsonify({"email": email, "reset_token": reset_token}), 200


@app.route("/reset_password", methods=["PUT"])
def update_password() -> str:
    """Updates password with a reset token"""
    try:
        email = request.form["email"]
        reset_token = request.form["reset_token"]
        new_password = request.form["new_password"]
    except KeyError:
        abort(400)

    try:
        AUTH.update_password(reset_token, new_password)
    except ValueError:
        abort(403)

    return jsonify({"email": email, "message": "Password updated"}), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
