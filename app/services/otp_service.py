import os
from flask_mail import Message
from ..extensions import mail


def _otp_html(otp: str, brand_name: str, brand_accent: str) -> str:
    """Render a modern HTML OTP email."""
    digits = list(str(otp).zfill(6))
    digit_cells = ''.join(
        f'<td style="padding:0 6px;text-align:center;">'
        f'<div style="'
        f'width:58px;height:72px;border-radius:16px;'
        f'background:linear-gradient(145deg,#f8fafc,#ffffff);'
        f'border:2.5px solid {brand_accent};'
        f'box-shadow:0 4px 14px rgba(0,0,0,.08),inset 0 1px 0 rgba(255,255,255,.9);'
        f'display:flex;align-items:center;justify-content:center;'
        f'font-size:32px;font-weight:900;color:#0f172a;font-family:monospace;'
        f'letter-spacing:-1px;'
        f'">{d}</div></td>'
        for d in digits
    )
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Verification Code — {brand_name}</title>
</head>
<body style="margin:0;padding:0;background:#f1f5f9;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#f1f5f9;padding:40px 0;">
    <tr><td align="center">

      <!-- Card -->
      <table width="520" cellpadding="0" cellspacing="0" style="background:#ffffff;border-radius:20px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,.08);max-width:520px;width:100%;">

        <!-- Header bar -->
        <tr>
          <td style="background:linear-gradient(135deg,{brand_accent} 0%,{brand_accent}dd 100%);padding:32px 40px 28px;text-align:center;">
            <div style="width:56px;height:56px;background:rgba(255,255,255,.18);border-radius:16px;display:inline-flex;align-items:center;justify-content:center;margin-bottom:14px;">
              <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
                <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
              </svg>
            </div>
            <div style="color:#ffffff;font-size:22px;font-weight:800;letter-spacing:-.3px;">{brand_name}</div>
            <div style="color:rgba(255,255,255,.75);font-size:13px;margin-top:4px;">Verification Code</div>
          </td>
        </tr>

        <!-- Body -->
        <tr>
          <td style="padding:36px 40px 28px;text-align:center;">
            <h2 style="margin:0 0 8px;font-size:20px;font-weight:700;color:#0f172a;">Verify your identity</h2>
            <p style="margin:0 0 28px;font-size:14px;color:#64748b;line-height:1.6;">
              Use the code below to complete your sign-in.<br>
              This code is valid for <strong style="color:#0f172a;">5 minutes</strong>.
            </p>

            <!-- OTP Digits -->
            <div style="display:flex;justify-content:center;gap:0;margin:0 auto 28px;overflow-x:auto;">
              <table cellpadding="0" cellspacing="0" style="margin:0 auto;border-collapse:separate;border-spacing:0;">
                <tr style="display:flex;justify-content:center;gap:8px;">{digit_cells}</tr>
              </table>
            </div>

            <!-- Copy hint -->
            <div style="display:inline-block;background:linear-gradient(135deg,#f8fafc,#f1f5f9);border:1.5px solid #e2e8f0;border-radius:12px;padding:12px 28px;font-size:13px;color:#64748b;margin-bottom:28px;box-shadow:0 2px 8px rgba(0,0,0,.05);">
              <span style="font-family:'Courier New',monospace;font-size:22px;font-weight:800;color:#0f172a;letter-spacing:8px;">{otp}</span>
              <span style="display:block;font-size:11px;color:#94a3b8;margin-top:4px;letter-spacing:.5px;">YOUR ONE-TIME CODE</span>
            </div>

            <!-- Warning box -->
            <div style="background:#fff7ed;border:1px solid #fed7aa;border-radius:10px;padding:14px 18px;text-align:left;">
              <div style="font-size:13px;color:#9a3412;font-weight:600;margin-bottom:4px;">
                ⚠️ Security notice
              </div>
              <div style="font-size:12px;color:#c2410c;line-height:1.6;">
                Never share this code with anyone — including {brand_name} staff.<br>
                If you didn't request this code, ignore this email.
              </div>
            </div>
          </td>
        </tr>

        <!-- Divider -->
        <tr><td style="padding:0 40px;"><div style="height:1px;background:#f1f5f9;"></div></td></tr>

        <!-- Footer -->
        <tr>
          <td style="padding:20px 40px 28px;text-align:center;">
            <p style="margin:0;font-size:12px;color:#94a3b8;line-height:1.7;">
              This is an automated message from <strong style="color:#64748b;">{brand_name}</strong>.<br>
              Please do not reply to this email.
            </p>
          </td>
        </tr>

      </table>
      <!-- /Card -->

    </td></tr>
  </table>
</body>
</html>"""


def send_otp_email(email: str, otp: str):
    # Try to get brand settings from Flask app config
    try:
        from flask import current_app
        brand_name   = current_app.config.get('BRAND_NAME', 'MikroMan')
        brand_accent = current_app.config.get('BRAND_ACCENT', '#2563eb')
    except Exception:
        brand_name   = os.getenv('BRAND_NAME', 'MikroMan')
        brand_accent = os.getenv('BRAND_ACCENT', '#2563eb')

    sender = os.getenv('MAIL_USERNAME', '')
    msg = Message(
        subject=f'Your {brand_name} verification code: {otp}',
        sender=sender,
        recipients=[email],
    )
    # Plain text fallback
    msg.body = (
        f'Your {brand_name} verification code is: {otp}\n\n'
        f'This code expires in 5 minutes.\n'
        f'If you did not request this, please ignore this email.'
    )
    # Modern HTML version
    msg.html = _otp_html(otp, brand_name, brand_accent)
    mail.send(msg)
