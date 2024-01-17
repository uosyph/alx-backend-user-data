#!/usr/bin/env python3
"""Module providing Session Authentication functionality."""

import uuid
from models.user import User
from api.v1.auth.auth import Auth


class SessionAuth(Auth):
    """Session Authentication class.

    Parameters:
        Auth (Type): Inherits from Auth class.
    """

    user_id_by_session_id = {}

    def create_session(self, user_id: str = None) -> str:
        """Create a session for the given user ID.

        Parameters:
            user_id (str, optional): The user ID. Defaults to None.

        Returns:
            str: A session ID if user_id is provided and is a string,
            otherwise None.
        """
        if not user_id or not isinstance(user_id, str):
            return None

        session_id = str(uuid.uuid4())
        self.user_id_by_session_id[session_id] = user_id

        return session_id
