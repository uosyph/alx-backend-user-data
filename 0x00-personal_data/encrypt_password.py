#!/usr/bin/env python3
"""
Module for password encryption using bcrypt.

This module provides functions for hashing and validating
passwords using the bcrypt hashing algorithm.
"""

import bcrypt


def hash_password(password: str) -> bytes:
    """
    Hashes a plaintext password using bcrypt.

    Parameters:
        password (str): The plaintext password to be hashed.

    Returns:
        bytes: The hashed password.
    """
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())


def is_valid(hashed_password: bytes, password: str) -> bool:
    """
    Validates a plaintext password against a hashed password using bcrypt.

    Parameters:
        hashed_password (bytes): The previously hashed password.
        password (str): The plaintext password to be validated.

    Returns:
        bool: True if the plaintext password matches the hashed password,
              False otherwise.
    """
    return bcrypt.checkpw(password.encode("utf-8"), hashed_password)
