#!/usr/bin/env python3
"""Module containing Session Authentication views."""

from os import getenv
from flask import abort, jsonify, request
from models.user import User
from api.v1.app import auth
from api.v1.views import app_views


@app_views.route("/auth_session/login",
                 methods=["POST"], strict_slashes=False)
def login():
    """Handle user login using Session Authentication.

    Endpoint:
        POST /auth_session/login/

    Request Parameters:
        - email (str): User's email address.
        - password (str): User's password.

    Returns:
        - JSON representation of the logged-in user.

    Raises:
        - 400 Bad Request: If email or password is missing in the request.
        - 401 Unauthorized: If the password is incorrect.
        - 404 Not Found: If no user is found for the provided email.
    """
    email = request.form.get("email")

    if not email:
        return jsonify({"error": "email missing"}), 400

    password = request.form.get("password")

    if not password:
        return jsonify({"error": "password missing"}), 400

    try:
        found_users = User.search({"email": email})
    except Exception:
        return jsonify({"error": "no user found for this email"}), 404

    if not found_users:
        return jsonify({"error": "no user found for this email"}), 404

    for user in found_users:
        if not user.is_valid_password(password):
            return jsonify({"error": "wrong password"}), 401

    user = found_users[0]
    session_id = auth.create_session(user.id)
    session_name = getenv("SESSION_NAME")
    user_dict = jsonify(user.to_json())
    user_dict.set_cookie(session_name, session_id)

    return user_dict


@app_views.route("/auth_session/logout",
                 methods=["DELETE"], strict_slashes=False)
def logout():
    """Handle user logout and destroy the session.

    Endpoint:
        DELETE /auth_session/logout

    Returns:
        Empty JSON response with HTTP status code 200 upon successful logout.

    Raises:
        - 404 Not Found: If the session cannot be destroyed.
    """
    destroy_session = auth.destroy_session(request)
    if not destroy_session:
        abort(404)

    return jsonify({}), 200
