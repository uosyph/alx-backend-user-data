#!/usr/bin/env python3
"""Module providing Session expiration authentication."""

from os import getenv
from datetime import datetime, timedelta
from api.v1.auth.session_auth import SessionAuth


class SessionExpAuth(SessionAuth):
    """Session authentication with expiration.

    Parameters:
        SessionAuth (Type): Inherits from SessionAuth class.
    """

    def __init__(self):
        """Initialize the SessionExpAuth instance."""
        self.session_duration = 0
        try:
            self.session_duration = int(getenv("SESSION_DURATION"))
        except Exception:
            pass

    def create_session(self, user_id=None):
        """Create a session with expiration.

        Parameters:
            user_id: User ID for the session.

        Returns:
            str: Session ID if successful, otherwise None.
        """
        if not user_id:
            return None

        session_id = super().create_session(user_id)
        if not session_id:
            return None

        user_id = self.user_id_by_session_id.get(session_id)
        if not user_id:
            return None

        session_dictionary = {"user_id": user_id, "created_at": datetime.now()}
        self.user_id_by_session_id[session_id] = session_dictionary
        return session_id

    def user_id_for_session_id(self, session_id=None):
        """Retrieve user ID for the given session ID with expiration.

        Parameters:
            session_id: Session ID to retrieve the user ID for.

        Returns:
            str: User ID if the session is valid, otherwise None.
        """
        if not session_id:
            return None

        session_dictionary = self.user_id_by_session_id.get(session_id)
        if not session_dictionary:
            return None

        user = session_dictionary.get("user_id")
        if not user:
            return None

        if self.session_duration <= 0:
            return user

        created_at = session_dictionary.get("created_at")
        if created_at is None:
            return None
        if (
            created_at + timedelta(seconds=self.session_duration)
            < datetime.now()
        ):
            return None

        return user
