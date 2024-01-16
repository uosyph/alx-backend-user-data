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

    def extract_base64_authorization_header(self,
                                            authorization_header: str) -> str:
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