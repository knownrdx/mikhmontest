from datetime import datetime, timezone
from ..extensions import mongo


def log_activity(user: str, action: str, details: str = "", **meta):
    """Insert an activity log entry.

    Backward compatible: callers can pass (user, action, details)
    Extra structured fields can be passed via **meta (e.g., created_by, qty, price, amount).
    """
    now = datetime.now(timezone.utc)
    doc = {
        'username': user,
        'action': action,
        'details': details,
        'timestamp': now.strftime('%Y-%m-%d %H:%M:%S'),
        'ts': now.isoformat()
    }
    if meta:
        # avoid overwriting core keys accidentally
        for k, v in meta.items():
            if k in doc:
                doc[f"meta_{k}"] = v
            else:
                doc[k] = v
    mongo.db.logs.insert_one(doc)
