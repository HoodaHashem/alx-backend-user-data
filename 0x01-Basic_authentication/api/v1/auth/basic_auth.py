#!/usr/bin/env python3
"""
Basic authentication module
"""
from api.v1.auth.auth import Auth
from typing import Type, List, Tuple
from base64 import b64decode
from models.user import User
from flask import request


class BasicAuth(Auth):
    """
    BasicAuth class
    """

    def extract_base64_authorization_header(self,
                                            authorization_header: str) -> str:
        """
        extract_base64_authorization_header
        """
        if authorization_header is None or not isinstance(
                                    authorization_header, str):
            return None
        if not authorization_header.startswith("Basic "):
            return None
        return authorization_header[6:]

    def decode_base64_authorization_header(self,
                                           base64_authorization_header:
                                           str) -> str:
        """
        decode_base64_authorization_header
        """
        if base64_authorization_header is None or not isinstance(
                            base64_authorization_header, str):
            return None
        try:
            return b64decode(base64_authorization_header).decode("utf-8")
        except Exception:
            return None

    def extract_user_credentials(self,
                                 decoded_base64_authorization_header:
                                 str) -> Tuple[str, str]:
        """
        extract_user_credentials
        """
        if decoded_base64_authorization_header is None or not isinstance(
                        decoded_base64_authorization_header, str):
            return None, None
        if ":" not in decoded_base64_authorization_header:
            return None, None
        return tuple(decoded_base64_authorization_header.split(":", 1))

    def user_object_from_credentials(self,
                                     user_email: str,
                                     user_pwd: str) -> Type[User]:
        """
        user_object_from_credentials
        """
        if user_email is None or not isinstance(user_email, str):
            return None
        if user_pwd is None or not isinstance(user_pwd, str):
            return None
        user = User()
        user.email = user_email
        user.password = user_pwd
        return user

    def current_user(self, request=None) -> Type[User]:
        """
        current_user
        """
        authorization_header = self.authorization_header(request)
        base64_authorization_header = self.extract_base64_authorization_header(
            authorization_header)
        decoded_base64_authorization_header = self.\
            decode_base64_authorization_header(base64_authorization_header)
        user_email, user_pwd = self.extract_user_credentials(
            decoded_base64_authorization_header)
        return self.user_object_from_credentials(user_email, user_pwd)
