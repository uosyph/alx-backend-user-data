#!/usr/bin/env python3
"""Module for managing API authentication."""

from flask import request
from typing import List, TypeVar


class Auth:
    """Class for managing API authentication."""

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """
        Check if authentication is required for the given path.

        Args:
            path (str): The requested path.
            excluded_paths (List[str]): List of exceptions.

        Returns:
            bool: True if authentication is required, False otherwise.
        """
        if excluded_paths is None or len(excluded_paths) == 0:
            return True

        for excluded_path in excluded_paths:
            if "*" in excluded_path:
                return not (path.startswith(excluded_path.replace("*", "")))

        return not (path in excluded_paths or f"{path}/" in excluded_paths)

    def authorization_header(self, request=None) -> str:
        """
        Get the Authorization header from the request.

        Args:
            request (flask.Request, optional): The request object.
            Defaults to None.

        Returns:
            str: The Authorization header value.
        """
        if request:
            return request.headers.get("Authorization")

    def current_user(self, request=None) -> TypeVar("User"):
        """
        Get the current user based on the request.

        Args:
            request (flask.Request, optional): The request object.
            Defaults to None.

        Returns:
            TypeVar('User'): The current user.
        """
        return None
