#!/usr/bin/env python3

"""
Auth module
"""


from flask import request
from typing import List, TypeVar
from os import getenv


class Auth:
    """Auth class"""

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """Require authentication"""
        if path is None or not excluded_paths:
            return True
        path = path + "/" if path[-1] != "/" else path
        has_wildcard = any(x.endswith("*") for x in excluded_paths)
        if not has_wildcard:
            return path not in excluded_paths
        for entry in excluded_paths:
            if entry.endswith("*"):
                if path.startswith(entry[:-1]):
                    return False
            if path == entry:
                return False
        return True

    def authorization_header(self, request=None) -> str:
        """Authorization header"""
        if request is None or "Authorization" not in request.headers:
            return None
        return request.headers["Authorization"]

    def current_user(self, request=None) -> TypeVar("User"):
        """Current user"""
        return None

    def session_cookie(self, request=None):
        """Session cookie"""
        if request is None:
            return None
        session_name = getenv("SESSION_NAME")
        return request.cookies.get(session_name)
