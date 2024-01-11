#!/usr/bin/env python3
"""Module for password encryption using bcrypt."""

import bcrypt


def hash_password(password: str) -> bytes:
    """Hashes a plaintext password using bcrypt."""
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())


def is_valid(hashed_password: bytes, password: str) -> bool:
    """Validates a plaintext password against a hashed password using bcrypt"""
    return bcrypt.checkpw(password.encode("utf-8"), hashed_password)
