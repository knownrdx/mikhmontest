import secrets
import string
from urllib.parse import urlparse


def parse_address(address: str):
    address = (address or '').strip().replace('http://', '').replace('https://', '')
    if ':' in address:
        host, port = address.split(':', 1)
        return host.strip(), int(port)
    return address.strip(), 8728


def generate_random_string(length: int, mode: str) -> str:
    if mode == 'upper_num':
        chars = string.ascii_uppercase + string.digits
    elif mode == 'lower_num':
        chars = string.ascii_lowercase + string.digits
    elif mode == 'mix':
        chars = string.ascii_letters + string.digits
    elif mode == 'num':
        chars = string.digits
    else:
        chars = string.ascii_lowercase + string.digits
    return ''.join(secrets.choice(chars) for _ in range(length))


def is_safe_url(target: str) -> bool:
    """Validate that a redirect target is a safe relative URL.

    Prevents open redirect attacks by ensuring the URL:
    - Is a relative path (starts with /)
    - Does not redirect to an external host (no // or scheme)
    """
    if not target:
        return False
    # Must start with exactly one slash (reject //, http://, etc.)
    if target.startswith('//') or target.startswith('\\'):
        return False
    parsed = urlparse(target)
    # Reject absolute URLs with a scheme (http, https, javascript, etc.)
    if parsed.scheme:
        return False
    # Reject URLs with a netloc (host component)
    if parsed.netloc:
        return False
    # Must start with /
    if not target.startswith('/'):
        return False
    return True
