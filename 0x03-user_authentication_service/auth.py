#!/usr/bin/env python3
"""Authentication Module

This module provides an Auth class for user authentication.
It interacts with a user database and includes methods for user registration,
login validation, session management, and password reset.
"""

import bcrypt
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.exc import InvalidRequestError
from uuid import uuid4
from typing import Union

from db import DB
from user import User


def _hash_password(password: str) -> bytes:
    """Hashes and salts the input password and returns it as bytes.

    Parameters:
        password (str): The input password.

    Returns:
        bytes: Salted and hashed password.
    """
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())


def _generate_uuid() -> str:
    """Generates a new UUID and returns its string representation.

    Returns:
        str: String representation of the new UUID.
    """
    return str(uuid4())


class Auth:
    """Auth class to interact with the authentication database."""

    def __init__(self):
        """Initializes an instance of the class with a database connection."""
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """Registers a new user with the given email and password.

        Parameters:
            email (str): The email of the new user.
            password (str): The password of the new user.

        Returns:
            User: The newly registered user.

        Raises:
            ValueError: If the user with the provided email already exists.
        """
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            hashed_password = _hash_password(password)
            user = self._db.add_user(email, hashed_password)
            return user
        else:
            raise ValueError(f"User {email} already exists")

    def valid_login(self, email: str, password: str) -> bool:
        """Checks if the login credentials (email and password) are valid.

        Parameters:
            email (str): The email of the user.
            password (str): The password of the user.

        Returns:
            bool: True if the login is valid, False otherwise.
        """
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            return False

        if bcrypt.checkpw(password.encode(), user.hashed_password):
            return True
        return False

    def create_session(self, email: str) -> str:
        """Creates a session ID for the user with the given email.

        Parameters:
            email (str): The email of the user.

        Returns:
            str: The session ID.

        Notes:
            If the user does not exist, returns None.
        """
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            return None

        session_id = _generate_uuid()
        self._db.update_user(user.id, session_id=session_id)
        return session_id

    def get_user_from_session_id(self, session_id: str) -> Union[str, None]:
        """Finds the user associated with the provided session ID.

        Parameters:
            session_id (str): The session ID.

        Returns:
            Union[str, None]: The user associated with the session ID,
            or None if not found.
        """
        if session_id is None:
            return None

        try:
            user = self._db.find_user_by(session_id=session_id)
        except NoResultFound:
            return None

        return user

    def destroy_session(self, user_id: int) -> None:
        """Updates the session ID of the user with the provided ID to None.

        Parameters:
            user_id (int): The ID of the user.
        """
        try:
            user = self._db.find_user_by(id=user_id)
        except NoResultFound:
            return None

        self._db.update_user(user.id, session_id=None)
        return None

    def get_reset_password_token(self, email: str) -> str:
        """Generates a reset password token for the user.

        Parameters:
            email (str): The email of the user.

        Returns:
            str: The reset password token.

        Raises:
            ValueError: If the user with the provided email does not exist.
        """
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            raise ValueError

        reset_token = _generate_uuid()
        self._db.update_user(user.id, reset_token=reset_token)
        return reset_token

    def update_password(self, reset_token: str, password: str) -> None:
        """Updates the user's password using the provided reset token.

        Parameters:
            reset_token (str): The reset password token.
            password (str): The new password.

        Raises:
            ValueError: If user with the provided reset token does not exist.
        """
        try:
            user = self._db.find_user_by(reset_token=reset_token)
        except NoResultFound:
            raise ValueError

        hashed_password = _hash_password(password)
        self._db.update_user(
            user.id,
            hashed_password=hashed_password,
            reset_token=None,
        )
