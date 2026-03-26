from datetime import timedelta
import os

_md_env = os.getenv('MAIN_DOMAIN', '')
_base_derived = '.'.join(_md_env.split('.')[-2:]) if _md_env.count('.') >= 2 else ''


class ProductionConfig:
    DEBUG = False
    SECRET_KEY = os.getenv('SECRET_KEY', 'CHANGE-ME')
    MONGO_URI = os.getenv('MONGO_URI')  # Required — must be Atlas URI
    ROUTER_SECRET_KEY = os.getenv('ROUTER_SECRET_KEY', '')

    SESSION_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    SESSION_COOKIE_SECURE = os.getenv('COOKIE_SECURE', '1').lower() in ('1', 'true', 'yes', 'on')
    REMEMBER_COOKIE_SECURE = os.getenv('COOKIE_SECURE', '1').lower() in ('1', 'true', 'yes', 'on')

    WTF_CSRF_TIME_LIMIT = None
    WTF_CSRF_SSL_STRICT = False

    if _base_derived and not any(x in _md_env for x in ('localhost', '127.0.0.1', '0.0.0.0')):
        _cookie_domain = os.getenv('SESSION_COOKIE_DOMAIN', f'.{_base_derived}')
    else:
        _cookie_domain = os.getenv('SESSION_COOKIE_DOMAIN', None)
    SESSION_COOKIE_DOMAIN = _cookie_domain if _cookie_domain else None

    REMEMBER_COOKIE_DURATION = timedelta(hours=12)
    PERMANENT_SESSION_LIFETIME = timedelta(hours=12)
    SESSION_PERMANENT = True

    # Mail
    MAIL_SERVER = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
    MAIL_PORT = int(os.getenv('MAIL_PORT', '587'))
    MAIL_USE_TLS = os.getenv('MAIL_USE_TLS', 'true').lower() in ('1', 'true', 'yes', 'on')
    MAIL_USE_SSL = os.getenv('MAIL_USE_SSL', 'false').lower() in ('1', 'true', 'yes', 'on')
    MAIL_USERNAME = os.getenv('MAIL_USERNAME', '')
    MAIL_PASSWORD = os.getenv('MAIL_PASSWORD', '')
    MAIL_DEFAULT_SENDER = os.getenv('MAIL_DEFAULT_SENDER', MAIL_USERNAME)

    APP_VERSION = '1.5.1'
    BRAND_NAME = os.getenv('BRAND_NAME', 'MikroMan')
    BRAND_ACCENT = os.getenv('BRAND_ACCENT', '#2563eb')

    SITE_DOMAIN = os.getenv('SITE_DOMAIN', '')
    MAIN_DOMAIN = _md_env


def get_config():
    return ProductionConfig
