"""
TOTP (Time-based One-Time Password) service.
Compatible with Google Authenticator, Aegis, Authy, and any TOTP app.
"""
import io
import base64
import pyotp
import qrcode
from qrcode.image.pure import PyPNGImage


def generate_totp_secret() -> str:
    """Generate a new random base32 TOTP secret."""
    return pyotp.random_base32()


def get_totp_uri(secret: str, username: str, issuer: str) -> str:
    """Get the otpauth:// URI for QR code generation."""
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=username, issuer_name=issuer)


def get_qr_base64(secret: str, username: str, issuer: str) -> str:
    """Generate QR code PNG as base64 string."""
    uri = get_totp_uri(secret, username, issuer)
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=6,
        border=3,
    )
    qr.add_data(uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="#0f172a", back_color="white")
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    return base64.b64encode(buf.getvalue()).decode('utf-8')


def verify_totp(secret: str, code: str) -> bool:
    """Verify a TOTP code. Allows 1 step window for clock drift."""
    if not secret or not code:
        return False
    try:
        totp = pyotp.TOTP(secret)
        return totp.verify(code.strip(), valid_window=1)
    except Exception:
        return False
