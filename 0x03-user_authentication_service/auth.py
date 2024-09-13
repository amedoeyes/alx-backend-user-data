#!/usr/bin/env python3

"""Auth module"""

import bcrypt
from db import DB
from user import User
from sqlalchemy.orm.exc import NoResultFound
import uuid


def _hash_password(password: str) -> bytes:
    """Hash a password"""
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())


def _generate_uuid() -> str:
    """Generate a new UUID"""
    return str(uuid.uuid4())


class Auth:
    """Auth class to interact with the authentication database."""

    def __init__(self):
        """Initialize a new Auth instance"""
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """Register user"""
        if not email or not password:
            return None
        try:
            self._db.find_user_by(email=email)
            raise ValueError("User {} already exists".format(email))
        except NoResultFound:
            return self._db.add_user(email, _hash_password(password))

    def valid_login(self, email: str, password: str) -> bool:
        """Validate login"""
        try:
            user = self._db.find_user_by(email=email)
            return bcrypt.checkpw(password.encode(), user.hashed_password)
        except NoResultFound:
            return False
        except ValueError:
            return False
        except TypeError:
            return False
        except Exception:
            return False
        return False

    def create_session(self, email: str) -> str:
        """Create session"""
        try:
            user = self._db.find_user_by(email=email)
            session_id = _generate_uuid()
            self._db.update_user(user.id, session_id=session_id)
            return session_id
        except NoResultFound:
            return None
        except ValueError:
            return None
        except TypeError:
            return None
        except Exception:
            return None
        return None

    def get_user_from_session_id(self, session_id: str) -> User:
        """Get user from session ID"""
        if not session_id:
            return None
        try:
            user = self._db.find_user_by(session_id=session_id)
            return user
        except NoResultFound:
            return None
        except ValueError:
            return None
        except TypeError:
            return None
        except Exception:
            return None
        return None

    def destroy_session(self, user_id: int) -> None:
        """Destroy session"""
        try:
            self._db.update_user(user_id, session_id=None)
        except Exception:
            return None
        return None

    def get_reset_password_token(self, email: str) -> str:
        """Get reset password token"""
        try:
            user = self._db.find_user_by(email=email)
            reset_token = _generate_uuid()
            self._db.update_user(user.id, reset_token=reset_token)
            return reset_token
        except NoResultFound:
            raise ValueError
        except Exception:
            raise ValueError

    def update_password(self, reset_token: str, password: str) -> None:
        """Update password"""
        try:
            user = self._db.find_user_by(reset_token=reset_token)
            self._db.update_user(
                user.id,
                hashed_password=_hash_password(password),
                reset_token=None,
            )
        except NoResultFound:
            raise ValueError
        except Exception:
            raise ValueError
