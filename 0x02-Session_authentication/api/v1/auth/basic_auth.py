#!/usr/bin/env python3
"""Module providing Basic Authentication functionality."""

import base64
import re
from typing import TypeVar
from models.user import User
from api.v1.auth.auth import Auth


class BasicAuth(Auth):
    """Class representing Basic Authentication.

    Parameters:
        Auth (Type): Inherits from Auth class.
    """

    def extract_base64_authorization_header(
            self, authorization_header: str
    ) -> str:
        """Extracts the Base64 part of the Authorization header.

        Parameters:
            authorization_header (str): The Authorization header.

        Returns:
            str: The Base64 part of the Authorization header.
        """
        if (
            not authorization_header
            or not isinstance(authorization_header, str)
        ):
            return None

        if re.search("^Basic ", authorization_header):
            return authorization_header.split(" ")[1]

    def decode_base64_authorization_header(
        self, base64_authorization_header: str
    ) -> str:
        """Decodes the Base64 Authorization header.

        Parameters:
            base64_authorization_header (str): The Base64 Authorization header.

        Returns:
            str: Decoded value of the Base64 string.
        """
        if (
            not base64_authorization_header
            or not isinstance(base64_authorization_header, str)
        ):
            return None

        try:
            return base64.b64decode(
                base64_authorization_header.encode("utf-8")).decode("utf-8")
        except Exception:
            return None

    def extract_user_credentials(
        self, decoded_base64_authorization_header: str
    ) -> (str, str):
        """Extracts user credentials from
        the decoded Base64 Authorization header.

        Parameters:
            decoded_base64_authorization_header (str): The decoded Base64
            Authorization header.

        Returns:
            Tuple[str, str]: A tuple containing user email and password.
        """
        if (
            not decoded_base64_authorization_header
            or not isinstance(decoded_base64_authorization_header, str)
        ):
            return (None, None)

        credentials = decoded_base64_authorization_header.split(":", 1)
        return (
            (credentials[0], credentials[1])
            if ":" in decoded_base64_authorization_header
            else (None, None)
        )

    def user_object_from_credentials(
        self, user_email: str, user_pwd: str
    ) -> TypeVar("User"):
        """Retrieves a User object based on the provided credentials.

        Parameters:
            user_email (str): User's email address.
            user_pwd (str): User's password.

        Returns:
            TypeVar("User"): The User object if found, otherwise None.
        """
        if (
            not user_email
            or not isinstance(user_email, str)
            or not user_pwd
            or not isinstance(user_pwd, str)
        ):
            return None

        try:
            users = User.search({"email": user_email})
            if not users:
                return None

            for user in users:
                if user.is_valid_password(user_pwd):
                    return user
        except Exception:
            return None

    def current_user(self, request=None) -> TypeVar("User"):
        """Returns the current user for a fully
        protected API with Basic Authentication.

        Parameters:
            request: Optional request object.

        Returns:
            TypeVar("User"): The current User object
            if authentication is successful, otherwise None.
        """
        try:
            header = self.authorization_header(request)
            base64_header = self.extract_base64_authorization_header(header)
            decode_base64_header = self.decode_base64_authorization_header(
                base64_header
            )
            user_email, user_pwd = self.extract_user_credentials(
                decode_base64_header
            )
            return self.user_object_from_credentials(user_email, user_pwd)
        except Exception:
            return None
