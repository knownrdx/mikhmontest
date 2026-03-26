import random
import uuid
from datetime import datetime, timezone, timedelta
from bson.objectid import ObjectId
from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from flask_login import login_user, logout_user, current_user
from werkzeug.security import check_password_hash, generate_password_hash
from pymongo.errors import ServerSelectionTimeoutError
from ..extensions import mongo, csrf as _csrf
from ..models.user import User
from ..services.otp_service import send_otp_email
from ..services.totp_service import verify_totp
from ..services.logger import log_activity
from ..utils.helpers import is_safe_url
from ..extensions import limiter

bp = Blueprint('auth', __name__)


# ─── Initial Setup (first-run admin creation) ─────────────────
_setup_done = False  # Cache: once an admin exists, stop checking DB


def needs_setup():
    """Return True if no admin user exists in the database."""
    global _setup_done
    if _setup_done:
        return False
    try:
        if mongo.db.users.count_documents({'role': 'admin'}, limit=1) > 0:
            _setup_done = True
            return False
        return True
    except Exception:
        return False


@bp.route('/setup', methods=['GET', 'POST'])
def setup():
    # Block if admin already exists
    if not needs_setup():
        return redirect(url_for('auth.login'))

    if request.method == 'POST':
        username = (request.form.get('username') or '').strip().lower()
        email = (request.form.get('email') or '').strip().lower()
        password = (request.form.get('password') or '').strip()
        confirm = (request.form.get('confirm_password') or '').strip()

        errors = []
        if not username or len(username) < 3:
            errors.append('Username must be at least 3 characters.')
        if not email or '@' not in email:
            errors.append('Valid email is required.')
        if not password or len(password) < 6:
            errors.append('Password must be at least 6 characters.')
        if password != confirm:
            errors.append('Passwords do not match.')

        if errors:
            for e in errors:
                flash(e, 'danger')
            return render_template('setup.html', form_data={'username': username, 'email': email})

        # Double-check no admin was created in the meantime
        if not needs_setup():
            flash('Admin already exists.', 'warning')
            return redirect(url_for('auth.login'))

        admin_doc = {
            'username': username,
            'email': email,
            'password': generate_password_hash(password),
            'role': 'admin',
            'is_admin': True,
            'status': 'active',
            'email_verified': True,
            'routers': [],
            'created_at': datetime.now(timezone.utc).isoformat(),
        }

        try:
            mongo.db.users.insert_one(admin_doc)
            flash('Super Admin created! Please login.', 'success')
            return redirect(url_for('auth.login'))
        except Exception as e:
            flash(f'Database error: {e}', 'danger')
            return render_template('setup.html', form_data={'username': username, 'email': email})

    return render_template('setup.html', form_data={})


_csrf.exempt(setup)


def _pool_connect_on_login(user_data: dict):
    """Pre-connect all user's routers in background after login."""
    try:
        from ..services.router_pool import router_pool

        sid = session.get('_pool_sid')
        if not sid:
            sid = str(uuid.uuid4())
            session['_pool_sid'] = sid

        routers = user_data.get('routers', []) or []

        # Admin: collect all routers from all users
        if user_data.get('role') == 'admin' or user_data.get('is_admin'):
            routers = []
            for u in mongo.db.users.find({'routers': {'$exists': True, '$ne': []}}):
                for r in (u.get('routers') or []):
                    routers.append(r)

        # Sub-admin: own + managed users' routers
        elif user_data.get('role') == 'sub-admin':
            seen = set()
            merged = []
            for r in (user_data.get('routers', []) or []):
                rid = r.get('id', '')
                if rid and rid not in seen:
                    seen.add(rid)
                    merged.append(r)
            staff_id = str(user_data.get('_id', ''))
            for u in mongo.db.users.find({'created_by': staff_id, 'routers': {'$exists': True, '$ne': []}}):
                for r in (u.get('routers') or []):
                    rid = r.get('id', '')
                    if rid and rid not in seen:
                        seen.add(rid)
                        merged.append(r)
            routers = merged

        if routers:
            router_pool.connect_all(sid, routers)
    except Exception:
        pass  # Pool failure should never block login

@bp.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute", methods=["POST"])
def login():
    # If already logged in, go to the originally requested page (next) or dashboard
    if current_user.is_authenticated:
        next_page = request.args.get('next')
        return redirect(next_page if is_safe_url(next_page) else url_for('dashboard.dashboard'))

    next_page = request.args.get('next')
    if next_page and not is_safe_url(next_page):
        next_page = None

    if request.method == 'POST':
        u_name = request.form.get('username')
        password = request.form.get('password')

        # Remember-me checkbox (stores cookie for 1 hour by config)
        remember = (request.form.get('remember') == 'on')

        # Prefer next from form (preserved through OTP step)
        next_page = request.form.get('next') or next_page

        try:
            user_data = mongo.db.users.find_one({'username': u_name})
        except ServerSelectionTimeoutError:
            flash('Database connection failed. Please start MongoDB or set MONGO_URI in your .env/config.', 'danger')
            return render_template('login.html', next=next_page), 503

        # Lockout check
        if user_data:
            lockout = user_data.get('lockout_until')
            if lockout:
                if isinstance(lockout, datetime):
                    lockout = lockout.replace(tzinfo=timezone.utc) if lockout.tzinfo is None else lockout
                if datetime.now(timezone.utc) < lockout:
                    remaining = int((lockout - datetime.now(timezone.utc)).total_seconds() / 60) + 1
                    log_activity(u_name, 'Login Failed', f'Account locked — tried from {request.headers.get("X-Forwarded-For", request.remote_addr or "?")}')
                    flash(f'Account locked. Try again in {remaining} minute(s).', 'danger')
                    return render_template('login.html', next=next_page)

        if user_data and check_password_hash(user_data['password'], password):
            # Check if email not yet verified
            if user_data.get('status') == 'pending_email':
                flash('Please verify your email first. Check your inbox for the OTP.', 'warning')
                return render_template('login.html', next=next_page)
            # Check if account is pending approval
            if user_data.get('status') == 'pending':
                flash('Your account is pending admin approval. Please wait for activation.', 'warning')
                return render_template('login.html', next=next_page)
            # Check if account is rejected/disabled
            if user_data.get('status') == 'rejected':
                flash('Your account has been rejected. Contact admin for details.', 'danger')
                return render_template('login.html', next=next_page)

            otp = str(random.randint(100000, 999999))
            try:
                otp_expiry = datetime.now(timezone.utc) + timedelta(minutes=5)
                mongo.db.users.update_one({'_id': user_data['_id']}, {'$set': {'otp': otp, 'otp_expiry': otp_expiry, 'is_verified': False}})
            except ServerSelectionTimeoutError:
                flash('Database connection failed. Please start MongoDB or set MONGO_URI in your .env/config.', 'danger')
                return render_template('login.html', next=next_page), 503

            # ── 2FA routing ──────────────────────────────────────────
            # two_fa_enabled: True = on, False/None/missing = off
            tfa_enabled = user_data.get('two_fa_enabled') is True
            tfa_method  = user_data.get('two_fa_method', 'off')

            if tfa_enabled and tfa_method == 'totp' and user_data.get('totp_secret'):
                # Authenticator app — show TOTP verify page
                return render_template('verify_totp_login.html',
                    user_id=str(user_data['_id']),
                    remember=remember,
                    next=next_page)

            if tfa_enabled and tfa_method == 'email' and user_data.get('email'):
                # Email OTP
                try:
                    send_otp_email(user_data['email'], otp)
                    flash('An OTP has been sent to your email.', 'info')
                    return render_template('verify_otp.html', user_id=str(user_data['_id']), remember=remember, next=next_page)
                except Exception:
                    flash('Failed to send email. Check configuration.', 'danger')
                    return redirect(url_for('auth.login', next=next_page))

            # Reset failed attempts on success
            if user_data.get('login_fails'):
                mongo.db.users.update_one({'_id': user_data['_id']}, {'$set': {'login_fails': 0, 'lockout_until': None}})

            # No 2FA / off — login directly
            login_user(User(user_data), remember=remember)
            ip = request.headers.get('X-Forwarded-For', request.remote_addr or 'unknown').split(',')[0].strip()
            mongo.db.users.update_one({'_id': user_data['_id']}, {'$set': {'last_login': datetime.now(timezone.utc), 'last_login_ip': ip}})
            log_activity(user_data.get('username','?'), 'Login', f'Login from {ip}')

            # Pre-connect all routers in background (session-based pool)
            _pool_connect_on_login(user_data)

            # If user hasn't finished first-time UI setup, send them there.
            if (user_data.get('role') or 'user') == 'user' and not user_data.get('ui_onboarded', False):
                return redirect(url_for('dashboard.ui_setup'))

            return redirect(next_page if is_safe_url(next_page) else url_for('dashboard.dashboard'))

        # Track failed login attempts (brute-force protection)
        if user_data:
            fails = int(user_data.get('login_fails', 0)) + 1
            lockout_until = None
            if fails >= 5:
                lockout_until = datetime.now(timezone.utc) + timedelta(minutes=15)
                flash(f'Too many failed attempts. Account locked for 15 minutes.', 'danger')
            else:
                flash(f'Invalid Credentials! ({fails}/5 attempts)', 'danger')
            mongo.db.users.update_one(
                {'_id': user_data['_id']},
                {'$set': {'login_fails': fails, 'lockout_until': lockout_until}}
            )
        else:
            # Unknown username — log attempt with IP for audit
            ip = request.headers.get('X-Forwarded-For', request.remote_addr or 'unknown').split(',')[0].strip()
            import logging
            logging.getLogger('security').warning(f'Failed login attempt for unknown user "{u_name}" from IP {ip}')
            flash('Invalid Credentials!', 'danger')

    return render_template('login.html', next=next_page)

@bp.route('/verify_otp', methods=['GET', 'POST'])
@limiter.limit("10 per minute", methods=["POST"])
def verify_otp():
    if request.method == 'POST':
        user_otp = request.form.get('otp')
        user_id = request.form.get('user_id')
        try:
            user_data = mongo.db.users.find_one({'_id': ObjectId(user_id)})
        except ServerSelectionTimeoutError:
            flash('Database connection failed. Please start MongoDB or set MONGO_URI in your .env/config.', 'danger')
            return redirect(url_for('auth.login'))
        # Check OTP expiry
        otp_expiry = user_data.get('otp_expiry') if user_data else None
        otp_expired = False
        if otp_expiry:
            if isinstance(otp_expiry, datetime):
                exp = otp_expiry.replace(tzinfo=timezone.utc) if otp_expiry.tzinfo is None else otp_expiry
                otp_expired = datetime.now(timezone.utc) > exp

        if otp_expired:
            mongo.db.users.update_one({'_id': user_data['_id']}, {'$set': {'otp': None}})
            flash('OTP expired. Please log in again.', 'danger')
            return redirect(url_for('auth.login'))

        if user_data and user_data.get('otp') == user_otp:
            try:
                mongo.db.users.update_one({'_id': user_data['_id']}, {'$set': {'is_verified': True, 'otp': None}})
            except ServerSelectionTimeoutError:
                flash('Database connection failed. Please start MongoDB or set MONGO_URI in your .env/config.', 'danger')
                return redirect(url_for('auth.login'))
            ip = request.headers.get('X-Forwarded-For', request.remote_addr or 'unknown').split(',')[0].strip()
            mongo.db.users.update_one({'_id': user_data['_id']}, {'$set': {
                'login_fails': 0, 'lockout_until': None,
                'last_login': datetime.now(timezone.utc),
                'last_login_ip': ip
            }})
            login_user(User(user_data), remember=(request.form.get('remember') == 'on'))
            flash('Verification successful!', 'success')
            _pool_connect_on_login(user_data)
            if (user_data.get('role') or 'user') == 'user' and not user_data.get('ui_onboarded', False):
                return redirect(url_for('dashboard.ui_setup'))
            next_page = request.form.get('next') or request.args.get('next')
            return redirect(next_page if is_safe_url(next_page) else url_for('dashboard.dashboard'))
        # Wrong OTP — re-render form with user_id + remember preserved
        flash('Invalid OTP! Please try again.', 'danger')
        return render_template(
            'verify_otp.html',
            user_id=request.form.get('user_id', ''),
            remember=request.form.get('remember', 'off'),
            next=request.form.get('next') or request.args.get('next'),
        )
    return render_template('verify_otp.html', next=request.args.get('next'))



@bp.route('/verify_totp_login', methods=['GET', 'POST'])
@limiter.limit("10 per minute", methods=["POST"])
def verify_totp_login():
    """Verify TOTP code during login."""
    if request.method == 'POST':
        user_id   = request.form.get('user_id', '')
        code      = (request.form.get('code') or '').replace(' ', '')
        remember  = request.form.get('remember', 'off')
        next_page = request.form.get('next') or request.args.get('next')

        if not user_id:
            flash('Session expired. Please log in again.', 'danger')
            return redirect(url_for('auth.login'))

        try:
            user_data = mongo.db.users.find_one({'_id': ObjectId(user_id)})
        except Exception:
            flash('Invalid session. Please log in again.', 'danger')
            return redirect(url_for('auth.login'))

        # Check TOTP lockout
        if user_data:
            from datetime import datetime, timezone
            tlock = user_data.get('totp_lockout')
            if tlock:
                tlock = tlock.replace(tzinfo=timezone.utc) if tlock.tzinfo is None else tlock
                if datetime.now(timezone.utc) < tlock:
                    flash('Account temporarily locked due to too many wrong codes.', 'danger')
                    return redirect(url_for('auth.login'))

        if user_data and verify_totp(user_data.get('totp_secret', ''), code):
            mongo.db.users.update_one({'_id': user_data['_id']}, {'$set': {'totp_fails': 0, 'totp_lockout': None}})
            login_user(User(user_data), remember=(remember == 'on'))
            ip = request.headers.get('X-Forwarded-For', request.remote_addr or 'unknown').split(',')[0].strip()
            mongo.db.users.update_one({'_id': user_data['_id']}, {'$set': {'last_login': datetime.now(timezone.utc), 'last_login_ip': ip}})
            flash('Verified!', 'success')
            _pool_connect_on_login(user_data)
            if (user_data.get('role') or 'user') == 'user' and not user_data.get('ui_onboarded', False):
                return redirect(url_for('dashboard.ui_setup'))
            return redirect(next_page if is_safe_url(next_page) else url_for('dashboard.dashboard'))

        # Track TOTP failed attempts separately
        if user_data:
            totp_fails = int(user_data.get('totp_fails', 0)) + 1
            totp_lock = None
            if totp_fails >= 5:
                from datetime import datetime, timezone, timedelta
                totp_lock = datetime.now(timezone.utc) + timedelta(minutes=10)
                flash('Too many wrong codes. Try again in 10 minutes.', 'danger')
                mongo.db.users.update_one({'_id': user_data['_id']}, {'$set': {'totp_fails': totp_fails, 'totp_lockout': totp_lock}})
                return redirect(url_for('auth.login'))
            mongo.db.users.update_one({'_id': user_data['_id']}, {'$set': {'totp_fails': totp_fails}})

        flash(f'Wrong code — please try again.', 'danger')
        return render_template('verify_totp_login.html',
            user_id=user_id,
            remember=remember,
            next=next_page,
        )

    return redirect(url_for('auth.login'))


@bp.route('/logout')
def logout():
    if current_user.is_authenticated:
        log_activity(current_user.username, 'Logout', 'User logged out')
    # Disconnect all pooled router connections for this session
    sid = session.get('_pool_sid')
    if sid:
        from ..services.router_pool import router_pool
        router_pool.disconnect_session(sid)
    logout_user()
    # logout_user() sets session['_remember'] = 'clear' so Flask-Login can
    # delete the remember_token cookie in its after_request hook.
    # We must preserve that signal before wiping the session, otherwise the
    # remember_token cookie is never removed and the user gets auto-logged-in.
    _fl_remember = session.get('_remember')
    session.clear()
    if _fl_remember:
        session['_remember'] = _fl_remember
    # Pre-generate a fresh CSRF token in the new empty session so the login
    # page renders correctly without a "CSRF session token missing" error.
    from flask_wtf.csrf import generate_csrf
    generate_csrf()
    return redirect(url_for('auth.login'))

# CSRF exemptions for auth forms (session token may not exist on first visit)
_csrf.exempt(login)
_csrf.exempt(verify_otp)
_csrf.exempt(verify_totp_login)
