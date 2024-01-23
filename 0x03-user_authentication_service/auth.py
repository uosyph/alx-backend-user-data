#!/usr/bin/env python3
""" Authentication
"""

from bcrypt import hashpw, gensalt, checkpw
from sqlalchemy.orm.exc import NoResultFound
from uuid import uuid4
from typing import TypeVar

from db import DB


def _hash_password(password: str) -> bytes:
    """
    Takes in string, converts to unicode
    Returns salted and hashed passwd as a bytestring
    """
    return hashpw(password.encode("utf-8"), gensalt())


def _generate_uuid() -> str:
    """Returns string representation of new UUID"""
    return str(uuid4())


class Auth:
    """Auth class to interact with the authentication database."""

    def __init__(self):
        """Instance"""
        self._db = DB()

    def register_user(self, email: str, password: str) -> TypeVar("User"):
        """Registers and returns a new user"""
        try:
            self._db.find_user_by(email=email)
            raise ValueError(f"User {email} already exists")
        except NoResultFound:
            hashed_password = _hash_password(password)
            new_user = self._db.add_user(email, hashed_password)
            return new_user

    def valid_login(self, email: str, password: str) -> bool:
        """Checks if user login is valid"""
        try:
            user = self._db.find_user_by(email=email)
            return checkpw(password.encode("utf-8"), user.hashed_password)
        except NoResultFound:
            return False
