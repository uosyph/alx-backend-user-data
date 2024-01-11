#!/usr/bin/env python3
"""Module for password encryption using bcrypt."""

from bcrypt import hashpw, gensalt, checkpw


def hash_password(password: str) -> bytes:
    """Hashes a plaintext password."""
    return hashpw(password.encode("utf-8"), gensalt())


def is_valid(hashed_password: bytes, password: str) -> bool:
    """Validates a plaintext password against a hashed password."""
    return checkpw(password.encode("utf-8"), hashed_password)
