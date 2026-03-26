import base64
import hashlib
import os
from typing import Optional

try:
    from cryptography.fernet import Fernet, InvalidToken
except Exception as e:  # pragma: no cover
    Fernet = None  # type: ignore
    InvalidToken = Exception  # type: ignore


def _derive_fernet_key(secret: str) -> bytes:
    """Derive a 32-byte urlsafe base64 key from an arbitrary secret string."""
    digest = hashlib.sha256((secret or '').encode('utf-8')).digest()
    return base64.urlsafe_b64encode(digest)


def get_fernet() -> "Fernet":
    """Return a Fernet instance.

    Key sources (in order):
    1) env ROUTER_SECRET_KEY (must be a valid Fernet key)
    2) env SECRET_KEY / fallback internal default -> derived key
    """
    if Fernet is None:
        raise RuntimeError(
            "Missing dependency: cryptography. Install it with `pip install cryptography`."
        )

    key = os.getenv('ROUTER_SECRET_KEY', '').strip()
    if key:
        return Fernet(key.encode('utf-8'))

    # Derive from SECRET_KEY to keep local/dev simple.
    # For production, set ROUTER_SECRET_KEY explicitly.
    app_secret = os.getenv('SECRET_KEY', 'mikroman_app_secret_default')
    return Fernet(_derive_fernet_key(app_secret))


def encrypt_text(plain: str) -> str:
    plain = (plain or '').strip()
    if not plain:
        return ''
    f = get_fernet()
    return f.encrypt(plain.encode('utf-8')).decode('utf-8')


def decrypt_text(token: str) -> str:
    token = (token or '').strip()
    if not token:
        return ''
    f = get_fernet()
    try:
        return f.decrypt(token.encode('utf-8')).decode('utf-8')
    except Exception as e:
        # Wrong key or corrupted token
        raise RuntimeError("Failed to decrypt router credential. Check ROUTER_SECRET_KEY/SECRET_KEY.") from e
