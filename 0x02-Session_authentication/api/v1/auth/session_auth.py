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

    def user_id_for_session_id(self, session_id: str = None) -> str:
        """Retrieve the user ID associated with a session ID.

        Parameters:
            session_id (str, optional): The session ID. Defaults to None.

        Returns:
            str: The user ID associated with the session ID.
        """
        if not session_id or not isinstance(session_id, str):
            return None

        return self.user_id_by_session_id.get(session_id)

    def current_user(self, request=None):
        """Retrieve the current user based on the session cookie.

        Parameters:
            request (object, optional): The request object. Defaults to None.

        Returns:
            User: The current User object if a valid session exists,
            otherwise None.
        """
        session_id = self.session_cookie(request)
        if not session_id:
            return None

        return User.get(self.user_id_for_session_id(session_id))

    def destroy_session(self, request=None):
        """Destroy the session associated with the given request.

        Parameters:
            request (object, optional): The request object. Defaults to None.

        Returns:
            bool: True if the session is successfully destroyed,
            False otherwise.
        """
        if not request:
            return False

        session_cookie = self.session_cookie(request)

        if not session_cookie:
            return False

        user_id = self.user_id_for_session_id(session_cookie)

        if not user_id:
            return False

        self.user_id_by_session_id.pop(session_cookie)
        return True
