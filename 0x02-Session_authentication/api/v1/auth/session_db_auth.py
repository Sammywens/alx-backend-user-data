#!/usr/bin/env python3
"""Session authentication with expiration
and storage support module for the API.
"""
from flask import request
from datetime import datetime, timedelta
from models.user_session import UserSession
from .session_exp_auth import SessionExpAuth


class SessionDBAuth(SessionExpAuth):
    """Session authentication class with
    expiration and storage support.
    """

    def create_session(self, user_id=None) -> str:
        """Creates and stores a session id for the user.
        """
        session_id = super().create_session(user_id)
        if isinstance(session_id, str):
            user_session = UserSession(user_id=user_id, session_id=session_id)
            user_session.save()
            return session_id

    def user_id_for_session_id(self, session_id=None):
        """Retrieves the user id of the user associated
        with a given session id.
        """
        try:
            sessions = UserSession.search({'session_id': session_id})
        except Exception:
            return None

        if not sessions or self.is_session_expired(sessions[0].created_at):
            return None

        return sessions[0].user_id

    def destroy_session(self, request=None) -> bool:
        """Destroys an authenticated session.
        """
        session_id = self.session_cookie(request)
        if not session_id:
            return False

        try:
            sessions = UserSession.search({'session_id': session_id})
        except Exception:
            return False

        if sessions:
            sessions[0].remove()
            return True

        return False

    def is_session_expired(self, created_at) -> bool:
        """Checks if a session is expired based on its creation time.
        """
        current_time = datetime.now()
        expiration_time = created_at + \
            timedelta(seconds=self.session_duration)
        return current_time > expiration_time
