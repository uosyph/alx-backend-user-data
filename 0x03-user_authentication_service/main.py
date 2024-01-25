#!/usr/bin/env python3
"""End-to-end integration test.

This script defines end-to-end integration tests for an Authentication Service.
It covers user registration, login, logout, profile retrieval,
password reset token generation, and password update functionalities.

Tests:
    - Test user registration.
    - Test login with incorrect password.
    - Test profile request without login (unauthenticated).
    - Test profile request after successful login.
    - Test logout functionality.
    - Test password reset token generation.
    - Test password update using a reset token.
    - Test login with the updated password.
"""

import requests

HOST = "http://localhost:5000"
EMAIL = "guillaume@holberton.io"
PASSWD = "b4l0u"
NEW_PASSWD = "t4rt1fl3tt3"


def register_user(email: str, password: str) -> None:
    """Test for validating user registration.

    Args:
        email (str): Email of the user to register.
        password (str): Password for the user.

    Raises:
        AssertionError: If the registration fails
        or the response does not match expectations.
    """
    data = {"email": email, "password": password}
    response = requests.post(f"{HOST}/users", data=data)

    assert response.status_code == 200
    assert response.json() == {"email": email, "message": "user created"}


def log_in_wrong_password(email: str, password: str) -> None:
    """Test for validating login with wrong password.

    Args:
        email (str): Email of the user.
        password (str): Incorrect password.

    Raises:
        AssertionError: If the login is successful
        or the response does not match expectations.
    """
    data = {"email": email, "password": password}
    response = requests.post(f"{HOST}/sessions", data=data)

    assert response.status_code == 401


def log_in(email: str, password: str) -> str:
    """Test for validating successful login.

    Args:
        email (str): Email of the user.
        password (str): Password for the user.

    Returns:
        str: Session ID obtained after successful login.

    Raises:
        AssertionError: If the login fails
        or the response does not match expectations.
    """
    data = {"email": email, "password": password}
    response = requests.post(f"{HOST}/sessions", data=data)

    assert response.status_code == 200
    assert response.json() == {"email": email, "message": "logged in"}

    return response.cookies.get("session_id")


def profile_unlogged() -> None:
    """Test for validating profile request without login.

    Raises:
        AssertionError: If the profile request is successful
        or the response does not match expectations.
    """
    cookies = {"session_id": ""}
    response = requests.get(f"{HOST}/profile", cookies=cookies)

    assert response.status_code == 403


def profile_logged(session_id: str) -> None:
    """Test for validating profile request after successful login.

    Args:
        session_id (str): Session ID obtained after login.

    Raises:
        AssertionError: If the profile request fails
        or the response does not match expectations.
    """
    cookies = {"session_id": session_id}
    response = requests.get(f"{HOST}/profile", cookies=cookies)

    assert response.status_code == 200
    assert response.json() == {"email": EMAIL}


def log_out(session_id: str) -> None:
    """Test for validating logout functionality.

    Args:
        session_id (str): Session ID obtained after login.

    Raises:
        AssertionError: If the logout fails
        or the response does not match expectations.
    """
    cookies = {"session_id": session_id}
    response = requests.delete(f"{HOST}/sessions", cookies=cookies)

    assert response.status_code == 200
    assert response.json() == {"message": "Bienvenue"}


def reset_password_token(email: str) -> str:
    """Test for validating password reset token generation.

    Args:
        email (str): Email of the user.

    Returns:
        str: Reset token obtained after the token generation.

    Raises:
        AssertionError: If the token generation fails
        or the response does not match expectations.
    """
    data = {"email": email}
    response = requests.post(f"{HOST}/reset_password", data=data)
    reset_token = response.json().get("reset_token")

    assert response.status_code == 200
    assert response.json() == {"email": email, "reset_token": reset_token}

    return reset_token


def update_password(email: str, reset_token: str, new_password: str) -> None:
    """Test for validating password reset (update).

    Args:
        email (str): Email of the user.
        reset_token (str): Reset token obtained for the user.
        new_password (str): New password to set for the user.

    Raises:
        AssertionError: If the password update fails
        or the response does not match expectations.
    """
    data = {"email": email,
            "reset_token": reset_token,
            "new_password": new_password}
    response = requests.put(f"{HOST}/reset_password", data=data)

    assert response.status_code == 200
    assert response.json() == {"email": email, "message": "Password updated"}


if __name__ == "__main__":
    register_user(EMAIL, PASSWD)
    log_in_wrong_password(EMAIL, NEW_PASSWD)
    profile_unlogged()
    session_id = log_in(EMAIL, PASSWD)
    profile_logged(session_id)
    log_out(session_id)
    reset_token = reset_password_token(EMAIL)
    update_password(EMAIL, reset_token, NEW_PASSWD)
    log_in(EMAIL, NEW_PASSWD)
