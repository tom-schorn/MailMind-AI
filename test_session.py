"""Thread-safe session storage for test logs."""

import threading
from datetime import datetime, timedelta
from typing import Dict, List

class TestSession:
    """Stores logs for a test session."""

    def __init__(self, session_id: str):
        self.session_id = session_id
        self.logs: List[Dict] = []
        self.status = 'running'
        self.created_at = datetime.now()
        self.lock = threading.Lock()

    def add_log(self, level: str, message: str):
        """Add a log entry."""
        with self.lock:
            self.logs.append({
                'timestamp': datetime.now().isoformat(),
                'level': level,
                'message': message
            })

    def get_logs(self, after_index: int = 0) -> List[Dict]:
        """Get logs after a certain index."""
        with self.lock:
            return self.logs[after_index:]

    def set_status(self, status: str):
        """Update session status."""
        with self.lock:
            self.status = status


class TestSessionManager:
    """Manages test sessions."""

    def __init__(self):
        self.sessions: Dict[str, TestSession] = {}
        self.lock = threading.Lock()

    def create_session(self, session_id: str) -> TestSession:
        """Create a new test session."""
        with self.lock:
            session = TestSession(session_id)
            self.sessions[session_id] = session
            return session

    def get_session(self, session_id: str) -> TestSession:
        """Get a test session."""
        with self.lock:
            return self.sessions.get(session_id)

    def cleanup_old_sessions(self, max_age_minutes: int = 30):
        """Remove sessions older than max_age_minutes."""
        with self.lock:
            cutoff = datetime.now() - timedelta(minutes=max_age_minutes)
            to_remove = [
                sid for sid, session in self.sessions.items()
                if session.created_at < cutoff
            ]
            for sid in to_remove:
                del self.sessions[sid]


# Global session manager
_session_manager = TestSessionManager()

def get_session_manager() -> TestSessionManager:
    """Get the global session manager."""
    return _session_manager
