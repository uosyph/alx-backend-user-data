#!/usr/bin/env python3
"""
Route module for the API
"""
from os import getenv
from api.v1.views import app_views
from flask import Flask, jsonify, abort, request
from flask_cors import CORS, cross_origin
from api.v1.auth.auth import Auth
from api.v1.auth.basic_auth import BasicAuth
from api.v1.auth.session_auth import SessionAuth
from api.v1.auth.session_exp_auth import SessionExpAuth
from api.v1.auth.session_db_auth import SessionDBAuth


app = Flask(__name__)
app.register_blueprint(app_views)
CORS(app, resources={r"/api/v1/*": {"origins": "*"}})

auth = None
if getenv("AUTH_TYPE") == "auth":
    auth = Auth()
elif getenv("AUTH_TYPE") == "basic_auth":
    auth = BasicAuth()
elif getenv("AUTH_TYPE") == "session_auth":
    auth = SessionAuth()
elif getenv("AUTH_TYPE") == "session_exp_auth":
    auth = SessionExpAuth()
elif getenv("AUTH_TYPE") == "session_db_auth":
    auth = SessionDBAuth()


@app.before_request
def authentication_handler() -> None:
    """Authentication handler before each request.

    Returns:
        None: Modifies the behavior of the request handling process.
    """
    exceptions = [
        "/api/v1/status/",
        "/api/v1/unauthorized/",
        "/api/v1/forbidden/",
        "/api/v1/auth_session/login/",
    ]

    if not auth or not auth.require_auth(request.path, exceptions):
        return None
    elif (
        not auth.authorization_header(request)
        and not auth.session_cookie(request)
    ):
        abort(401)
    elif not auth.current_user(request):
        abort(403)
    request.current_user = auth.current_user(request)


@app.errorhandler(404)
def not_found(error) -> str:
    """Not found handler"""
    return jsonify({"error": "Not found"}), 404


@app.errorhandler(401)
def unauthorized(error) -> str:
    """Handles unauthorized access error.

    Parameters:
        error (Exception): The exception object representing the error.

    Returns:
        str: JSON response containing an error message for unauthorized access.
    """
    return jsonify({"error": "Unauthorized"}), 401


@app.errorhandler(403)
def forbidden(error) -> str:
    """Handles forbidden access error.

    Parameters:
        error (Exception): The exception object representing the error.

    Returns:
        str: JSON response containing an error message for forbidden access.
    """
    return jsonify({"error": "Forbidden"}), 403


if __name__ == "__main__":
    host = getenv("API_HOST", "0.0.0.0")
    port = getenv("API_PORT", "5000")
    app.run(host=host, port=port)
