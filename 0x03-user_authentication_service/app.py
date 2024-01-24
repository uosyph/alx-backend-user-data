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


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
