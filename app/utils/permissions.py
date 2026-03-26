"""Permission helpers.

`admin` has full access. Everyone else uses boolean flags stored on the
MongoDB `users` document.

Flags used by this app:
- can_generate           — Voucher generation
- allow_reports          — Sales reports
- allow_monitor          — Monitor page (live active users)
- allow_user_manage      — Hotspot user CRUD
- allow_profiles         — View profile list
- allow_profile_edit     — Add/edit profiles
- allow_quick_user       — Quick User page
- allow_mac_reset        — Reset user MAC
- allow_live_template    — Live voucher template editor
- allow_router_manage    — Router management for users
- allow_export_pdf       — Export vouchers as PDF
- allow_create_user      — Create new users (sub-admin)
- allow_delete_user      — Delete users (sub-admin)
- allow_batch_delete     — Batch delete hotspot logs
- allow_port_lock       — Bridge port lock/unlock (hotspot ↔ free)
"""

from __future__ import annotations

from functools import wraps

from bson.objectid import ObjectId
from flask import abort
from flask_login import current_user

from ..extensions import mongo


def _to_bool(v) -> bool:
    return v is True or v in (1, "1", "true", "True", "yes", "on", "ON")


def get_user_doc() -> dict:
    """Load a fresh copy of the current user from DB."""
    if not getattr(current_user, "is_authenticated", False):
        return {}
    try:
        return mongo.db.users.find_one({"_id": ObjectId(current_user.id)}) or {}
    except Exception:
        return {}


def is_admin(user_doc: dict | None = None) -> bool:
    d = user_doc or get_user_doc()
    return d.get("role") == "admin"


def has_flag(flag: str, user_doc: dict | None = None) -> bool:
    d = user_doc or get_user_doc()
    if is_admin(d):
        return True
    return _to_bool(d.get(flag))


def require_admin(fn):
    @wraps(fn)
    def _wrapped(*args, **kwargs):
        if not is_admin():
            abort(403)
        return fn(*args, **kwargs)

    return _wrapped


def require_flag(flag: str):
    """Decorator: allow admin OR users with the given boolean flag."""

    def decorator(fn):
        @wraps(fn)
        def _wrapped(*args, **kwargs):
            d = get_user_doc()
            if is_admin(d):
                return fn(*args, **kwargs)
            if not _to_bool(d.get(flag)):
                abort(403)
            return fn(*args, **kwargs)

        return _wrapped

    return decorator


def require_any(*flags: str):
    """Decorator: allow admin OR users with ANY of the flags."""

    def decorator(fn):
        @wraps(fn)
        def _wrapped(*args, **kwargs):
            if is_admin():
                return fn(*args, **kwargs)
            d = get_user_doc()
            if not any(_to_bool(d.get(f)) for f in flags):
                abort(403)
            return fn(*args, **kwargs)

        return _wrapped

    return decorator
