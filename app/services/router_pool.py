"""
Router Connection Pool Manager
================================
Session-based persistent MikroTik API connections.

- Login → all routers connect in background
- Connections cached in memory → no reconnect on refresh
- Session expire / logout → auto disconnect all
- Dead connection → auto reconnect transparently
- Thread-safe for Flask's multi-threaded server

Usage:
    from app.services.router_pool import router_pool

    # Get cached connection (auto-connects if needed)
    api = router_pool.get_api(session_id, router_dict)

    # Connect all routers for a session (call on login)
    router_pool.connect_all(session_id, routers_list)

    # Disconnect all on logout
    router_pool.disconnect_session(session_id)
"""

import threading
import time
import logging
import atexit
from typing import Optional

import routeros_api

from ..utils.helpers import parse_address
from ..utils.crypto import decrypt_text

logger = logging.getLogger(__name__)

# How long (seconds) an idle session's connections live before auto-cleanup
SESSION_TTL = 3700  # ~1 hour + 100s buffer

# Heartbeat interval: how often the cleaner thread runs
CLEANER_INTERVAL = 120  # every 2 minutes

# Connection health check timeout
HEALTH_CHECK_TIMEOUT = 5


class _RouterEntry:
    """Single cached router connection."""

    __slots__ = ('conn', 'api', 'router_dict', 'created_at', 'last_used', 'lock')

    def __init__(self, conn, api, router_dict: dict):
        self.conn = conn
        self.api = api
        self.router_dict = router_dict
        self.created_at = time.time()
        self.last_used = time.time()
        self.lock = threading.Lock()

    def touch(self):
        self.last_used = time.time()

    def is_alive(self) -> bool:
        """Quick health check — try a lightweight API call."""
        try:
            self.api.get_resource('/system/identity').get()
            return True
        except Exception:
            return False

    def close(self):
        """Safely disconnect."""
        try:
            self.conn.disconnect()
        except Exception:
            pass


class _SessionEntry:
    """All router connections for one user session."""

    __slots__ = ('routers', 'created_at', 'last_activity', 'lock')

    def __init__(self):
        self.routers: dict[str, _RouterEntry] = {}  # router_id -> _RouterEntry
        self.created_at = time.time()
        self.last_activity = time.time()
        self.lock = threading.Lock()

    def touch(self):
        self.last_activity = time.time()

    def is_expired(self) -> bool:
        return (time.time() - self.last_activity) > SESSION_TTL

    def close_all(self):
        with self.lock:
            for rid, entry in self.routers.items():
                entry.close()
            self.routers.clear()


class RouterConnectionPool:
    """
    Global, thread-safe router connection pool.

    Keyed by Flask session ID → router connections.
    Automatically cleans up expired sessions.
    """

    def __init__(self):
        self._sessions: dict[str, _SessionEntry] = {}
        self._lock = threading.Lock()
        self._cleaner_running = False
        self._cleaner_thread: Optional[threading.Thread] = None

    # ── Public API ────────────────────────────────────────────

    def get_api(self, session_id: str, router: dict):
        """
        Get a cached API connection for a router.
        Auto-connects if not cached or connection is dead.

        Returns: routeros_api.Api object (ready to use)
        Raises: Exception if connection fails
        """
        if not session_id or not router:
            return self._make_fresh_connection(router)

        router_id = router.get('id', '')
        if not router_id:
            return self._make_fresh_connection(router)

        self._ensure_cleaner()

        sess = self._get_or_create_session(session_id)
        sess.touch()

        with sess.lock:
            entry = sess.routers.get(router_id)

            if entry:
                entry.touch()
                try:
                    if entry.is_alive():
                        return entry.api
                except Exception:
                    pass
                # Dead — clean up and reconnect
                entry.close()
                del sess.routers[router_id]

            conn, api = self._connect_router(router)
            sess.routers[router_id] = _RouterEntry(conn, api, router)
            return api

    def get_api_and_conn(self, session_id: str, router: dict):
        """
        Get both conn and api (for backward compatibility).
        Returns: (DummyConn, api) — DummyConn.disconnect() is a no-op
        """
        api = self.get_api(session_id, router)
        return _DummyConn(), api

    def connect_all(self, session_id: str, routers: list):
        """
        Pre-connect all routers for a session (call on login).
        Runs in background thread so login isn't blocked.
        """
        if not session_id or not routers:
            return

        self._ensure_cleaner()

        def _bg_connect():
            for r in routers:
                rid = r.get('id', '')
                if not rid:
                    continue
                try:
                    self.get_api(session_id, r)
                    logger.info(f"Pool: connected router '{r.get('name', rid)}' for session {session_id[:8]}...")
                except Exception as e:
                    logger.warning(f"Pool: failed to connect router '{r.get('name', rid)}': {e}")

        t = threading.Thread(target=_bg_connect, daemon=True, name=f"pool-connect-{session_id[:8]}")
        t.start()

    def disconnect_session(self, session_id: str):
        """Disconnect all routers for a session (call on logout)."""
        if not session_id:
            return

        with self._lock:
            sess = self._sessions.pop(session_id, None)

        if sess:
            sess.close_all()
            logger.info(f"Pool: disconnected all routers for session {session_id[:8]}...")

    def get_pool_stats(self) -> dict:
        """Get pool statistics (for admin dashboard)."""
        with self._lock:
            total_sessions = len(self._sessions)
            total_connections = sum(
                len(s.routers) for s in self._sessions.values()
            )
            active_sessions = sum(
                1 for s in self._sessions.values() if not s.is_expired()
            )

        return {
            'total_sessions': total_sessions,
            'active_sessions': active_sessions,
            'total_connections': total_connections,
        }

    def disconnect_all(self):
        """Disconnect everything (call on app shutdown)."""
        with self._lock:
            for sid, sess in self._sessions.items():
                sess.close_all()
            self._sessions.clear()
        logger.info("Pool: all connections closed (shutdown)")

    # ── Internal ──────────────────────────────────────────────

    def _get_or_create_session(self, session_id: str) -> _SessionEntry:
        with self._lock:
            if session_id not in self._sessions:
                self._sessions[session_id] = _SessionEntry()
            return self._sessions[session_id]

    def _connect_router(self, router: dict):
        """Create a new RouterOS API connection."""
        ip, port = parse_address(router.get('ip', ''))
        if router.get('api_port'):
            port = int(router['api_port'])
        password = (
            decrypt_text(router.get('api_pass_enc', ''))
            if router.get('api_pass_enc')
            else router.get('api_pass', '')
        )
        conn = routeros_api.RouterOsApiPool(
            ip,
            username=router.get('api_user', ''),
            password=password,
            port=port,
            plaintext_login=True,
        )
        api = conn.get_api()
        return conn, api

    def _make_fresh_connection(self, router: dict):
        """Fallback: one-off connection (no pooling)."""
        _, api = self._connect_router(router)
        return api

    def _ensure_cleaner(self):
        """Start the background cleaner thread if not already running."""
        if self._cleaner_running:
            return

        with self._lock:
            if self._cleaner_running:
                return
            self._cleaner_running = True
            self._cleaner_thread = threading.Thread(
                target=self._cleaner_loop,
                daemon=True,
                name="pool-cleaner"
            )
            self._cleaner_thread.start()

    def _cleaner_loop(self):
        """Background loop: remove expired sessions and dead connections."""
        while True:
            try:
                time.sleep(CLEANER_INTERVAL)
                self._cleanup_expired()
            except Exception as e:
                logger.error(f"Pool cleaner error: {e}")

    def _cleanup_expired(self):
        """Remove sessions that have expired."""
        expired_ids = []

        with self._lock:
            for sid, sess in self._sessions.items():
                if sess.is_expired():
                    expired_ids.append(sid)

        for sid in expired_ids:
            self.disconnect_session(sid)
            logger.info(f"Pool: auto-cleaned expired session {sid[:8]}...")


class _DummyConn:
    """
    Dummy connection object that makes conn.disconnect() a no-op.
    Used for backward compatibility with existing code that calls conn.disconnect().
    """

    def disconnect(self):
        pass  # No-op — pool manages the lifecycle


# ── Global singleton ──────────────────────────────────────────
router_pool = RouterConnectionPool()

# Clean up on process exit
atexit.register(router_pool.disconnect_all)
