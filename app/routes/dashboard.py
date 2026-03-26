from bson.objectid import ObjectId
from datetime import datetime, timedelta, timezone
import re
from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify
from flask_login import login_required, current_user
from werkzeug.security import generate_password_hash

from ..extensions import mongo
from ..services.totp_service import generate_totp_secret, get_qr_base64, verify_totp
from ..services.mikrotik import get_api, get_api_pooled
from ..services.router_pool import router_pool
from ..utils.parsing import parse_activation_log
from ..utils.permissions import require_any


def _get_session_id() -> str:
    """Get stable session id for connection pool."""
    import uuid
    sid = session.get('_pool_sid')
    if not sid:
        sid = session.get('_id') or str(uuid.uuid4())
        session['_pool_sid'] = sid
    return sid


def _get_pool_api(router: dict):
    """Get pooled API connection. Falls back to fresh if pool fails."""
    try:
        sid = _get_session_id()
        return get_api_pooled(router, session_id=sid)
    except Exception:
        return get_api(router)

def _month_start(dt: datetime) -> datetime:
    return datetime(dt.year, dt.month, 1)

def _add_months(dt: datetime, months: int) -> datetime:
    y = dt.year + (dt.month - 1 + months) // 12
    m = (dt.month - 1 + months) % 12 + 1
    return datetime(y, m, 1)

def _last_n_month_keys(n: int = 6):
    now = datetime.now(timezone.utc)
    start = _add_months(_month_start(now), -(n-1))
    keys = []
    labels = []
    for i in range(n):
        d = _add_months(start, i)
        key = f"{d.year:04d}-{d.month:02d}"
        keys.append(key)
        labels.append(d.strftime("%b %Y"))
    return keys, labels


bp = Blueprint('dashboard', __name__)


def _landing_endpoint_for(user: dict) -> str:
    """Resolve a safe landing endpoint based on user preference and permissions."""
    role = (user.get('role') or 'user')
    pref = (user.get('ui_landing') or 'dashboard')

    # Staff: default to staff panel
    if role == 'sub-admin':
        return 'dashboard.staff_panel'

    if role != 'user':
        return 'dashboard.dashboard'

    # Normal user options
    if pref == 'profile':
        return 'dashboard.profile'
    # For everything else, keep dashboard
    return 'dashboard.dashboard'


@bp.route('/ui-setup', methods=['GET', 'POST'])
@login_required
def ui_setup():
    """First-login UI setup for normal users.

    Asks user what layout they prefer (navbar/sidebar) and where to land.
    """
    user_data = mongo.db.users.find_one({'_id': ObjectId(current_user.id)}) or {}

    if request.method == 'POST':
        layout = (request.form.get('layout') or 'full').strip()
        landing = (request.form.get('landing') or 'dashboard').strip()

        ui_navbar = layout in ('full', 'navbar')
        ui_sidebar = layout in ('full', 'sidebar')

        if landing not in ('dashboard', 'profile'):
            landing = 'dashboard'

        mongo.db.users.update_one(
            {'_id': ObjectId(current_user.id)},
            {'$set': {
                'ui_navbar': ui_navbar,
                'ui_sidebar': ui_sidebar,
                'ui_landing': landing,
                'ui_onboarded': True,
            }}
        )

        # Redirect to landing
        if landing == 'profile':
            return redirect(url_for('dashboard.profile'))
        return redirect(url_for('dashboard.dashboard'))

    return render_template('ui_setup.html', user_data=user_data)


@bp.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    """Profile page: update email, password, and UI preferences."""
    user_data = mongo.db.users.find_one({'_id': ObjectId(current_user.id)}) or {}
    if request.method == 'POST':
        email = (request.form.get('email') or '').strip()
        new_pass = (request.form.get('new_password') or '').strip()

        # UI preferences (available for all roles; landing only for normal users)
        layout = (request.form.get('layout') or '').strip()
        landing = (request.form.get('landing') or '').strip()

        updates = {}
        if email:
            updates['email'] = email
        if new_pass:
            if len(new_pass) < 6:
                flash('Password must be at least 6 characters.', 'danger')
                return redirect(url_for('dashboard.profile'))
            updates['password'] = generate_password_hash(new_pass)

        if layout:
            ui_navbar = layout in ('full', 'navbar')
            ui_sidebar = layout in ('full', 'sidebar')
            updates['ui_navbar'] = ui_navbar
            updates['ui_sidebar'] = ui_sidebar

        # Landing preference only for normal users
        if layout or landing:
            if (user_data.get('role') or 'user') == 'user':
                if landing not in ('dashboard', 'profile'):
                    landing = 'dashboard'
                if landing:
                    updates['ui_landing'] = landing
                updates['ui_onboarded'] = True

        if updates:
            mongo.db.users.update_one({'_id': ObjectId(current_user.id)}, {'$set': updates})
            flash('Profile updated', 'success')

        return redirect(url_for('dashboard.profile'))

    return render_template('profile.html', user_data=user_data)

@bp.route('/dashboard')
@login_required
def dashboard():
    user_data = mongo.db.users.find_one({'_id': ObjectId(current_user.id)})
    settings = mongo.db.settings.find_one({'support_contact': {'$exists': True}})

    # First-login prompt: show setup page if not yet onboarded
    if user_data and not user_data.get('ui_onboarded', False):
        return redirect(url_for('dashboard.ui_setup'))

    # If user has a non-default landing preference, route them there.
    if user_data and (user_data.get('role') or 'user') == 'user' and user_data.get('ui_onboarded', False):
        ep = _landing_endpoint_for(user_data)
        if ep == 'dashboard.profile':
            return redirect(url_for('dashboard.profile'))

    if current_user.role == 'admin':
        users_data = list(mongo.db.users.find({'role': {'$ne': 'admin'}}))
        # Fetch system info for each router (for dashboard cards)
        # Router info loaded lazily via /api/router-status (background fetch)
        all_router_info = []
        logs = list(mongo.db.logs.find().sort('timestamp', -1).limit(500))

        # --- Admin analytics (revenue & trend) ---
        now_utc = datetime.now(timezone.utc)
        start_7d = (now_utc - timedelta(days=7)).isoformat()
        month_start = datetime(now_utc.year, now_utc.month, 1).isoformat()

        def _safe_amount(doc):
            # Prefer structured amount; fall back to parsing details
            if isinstance(doc.get('amount'), (int, float)):
                return float(doc.get('amount') or 0.0)
            det = (doc.get('details') or '')
            # details example: qty=10, price=20, ...
            try:
                mq = re.search(r'qty=(\d+)', det)
                mp = re.search(r'price=([0-9\.]+)', det)
                if mq and mp:
                    return float(mq.group(1)) * float(mp.group(1))
            except Exception:
                pass
            return 0.0

        # Revenue last 7 days
        logs_7d = list(mongo.db.logs.find({'action': 'generate_vouchers', 'ts': {'$gte': start_7d}}))
        revenue_7d = sum(_safe_amount(d) for d in logs_7d)

        # Revenue this month
        logs_m = list(mongo.db.logs.find({'action': 'generate_vouchers', 'ts': {'$gte': month_start}}))
        revenue_month = sum(_safe_amount(d) for d in logs_m)

        # Trend: last 6 months
        month_keys, month_labels = _last_n_month_keys(6)
        rev_by_m = {k: 0.0 for k in month_keys}
        vou_by_m = {k: 0 for k in month_keys}

        trend_docs = list(mongo.db.logs.find({'action': 'generate_vouchers'}))
        for d in trend_docs:
            ts = (d.get('ts') or '')[:7]  # YYYY-MM
            if ts in rev_by_m:
                rev_by_m[ts] += _safe_amount(d)
                if isinstance(d.get('qty'), int):
                    vou_by_m[ts] += int(d.get('qty') or 0)
                else:
                    # fallback: count 1 event if qty missing
                    vou_by_m[ts] += 1

        admin_trend = {
            'labels': month_labels,
            'revenue': [round(rev_by_m[k], 2) for k in month_keys],
            'vouchers': [vou_by_m[k] for k in month_keys],
        }

        admin_stats = {
            'total_users': mongo.db.users.count_documents({'role': 'user'}),
            'total_staff': mongo.db.users.count_documents({'role': 'sub-admin'}),
            'routers_total': sum(len(u.get('routers', []) or []) for u in users_data),
            'vouchers_7d': mongo.db.logs.count_documents({'action': 'generate_vouchers', 'ts': {'$gte': start_7d}}),
            'revenue_7d': f"{revenue_7d:.2f}",
            'revenue_month': f"{revenue_month:.2f}",
        }
        admin_user_data = mongo.db.users.find_one({'_id': ObjectId(current_user.id)}) or {}
        # Pending registrations (approval queue)
        pending_users = list(mongo.db.users.find({'status': 'pending'}).sort('created_at', -1))
        return render_template('admin_panel.html', users=users_data, settings=settings, logs=logs, admin_stats=admin_stats, admin_trend=admin_trend, user_data=admin_user_data, all_router_info=all_router_info, pending_users=pending_users)

    # Sub-admin: render admin_panel with limited context (no env/config access)
    if user_data and user_data.get('role') == 'sub-admin':
        # Only show users created by this sub-admin
        sub_users = list(mongo.db.users.find({'created_by': str(user_data.get('_id'))}))
        # Don't check router status synchronously — too slow with many routers.
        # Status will be fetched asynchronously via /api/router-status (same as admin dashboard).
        for u in sub_users:
            for r in u.get('routers', []):
                r['status'] = 'Unknown'  # Will be updated by background JS fetch
        sub_profiles = []
        sub_selected_id = request.args.get('router_id') or session.get('router_id')
        if request.args.get('router_id'):
            session['router_id'] = request.args.get('router_id')
        # Collect all routers for this sub-admin: own + managed users
        from ..routes.admin import _get_accessible_routers as _gar
        all_sub_routers = _gar(user_data)

        sub_router = next((r for r in all_sub_routers
                           if r.get('id') == sub_selected_id),
                          all_sub_routers[0] if all_sub_routers else None)
        if sub_router and user_data.get('can_generate'):
            try:
                conn, api = _get_pool_api(sub_router)
                sub_profiles = [p.get('name') for p in api.get_resource('/ip/hotspot/user/profile').get() if p.get('name')]
                conn.disconnect()
            except Exception:
                pass
        return render_template('admin_panel.html',
            users=sub_users,
            settings={},
            logs=[],
            admin_stats=None,
            admin_trend=None,
            user_data=user_data,
            sub_admin_mode=True,          # template uses this to hide sensitive sections
            profiles=sub_profiles,
            selected_sub_router=sub_router,
            all_routers=all_sub_routers,
            selected_router=sub_router,
            can_generate=user_data.get('can_generate', False),
            can_user_manage=user_data.get('allow_user_manage', False),
            can_reports=user_data.get('allow_reports', False),
            can_profiles=user_data.get('allow_profiles', False),
            can_profile_edit=user_data.get('allow_profile_edit', False),
            can_quick_user=user_data.get('allow_quick_user', False),
            can_mac_reset=user_data.get('allow_mac_reset', False),
            can_live_template=user_data.get('allow_live_template', False),
            can_router_manage=user_data.get('allow_router_manage', False),
            can_export_pdf=user_data.get('allow_export_pdf', False),
            can_monitor=user_data.get('allow_monitor', False),
            can_port_lock=user_data.get('allow_port_lock', False),
            can_batch_delete=user_data.get('allow_batch_delete', False),
            is_staff=True,
        )

    routers = user_data.get('routers', []) if user_data else []
    selected_id = request.args.get('router_id') or session.get('router_id')
    if request.args.get('router_id'):
        session['router_id'] = request.args.get('router_id')
    router = next((r for r in routers if r.get('id') == selected_id), routers[0] if routers else None)

    live_data = {'active_count': 0, 'total_users': 0, 'system': {}, 'income_today': 0.0, 'income_month': 0.0, 'sells_today': 0, 'sells_month': 0, 'interfaces': []}

    if router:
        try:
            conn, api = _get_pool_api(router)
            live_data['active_count'] = len(api.get_resource('/ip/hotspot/active').get())
            live_data['total_users'] = len(api.get_resource('/ip/hotspot/user').get())
            live_data['interfaces'] = api.get_resource('/interface').get()
            res = api.get_resource('/system/resource').get()
            if res:
                live_data['system'] = res[0]

            if user_data and user_data.get('allow_reports'):
                scripts = api.get_resource('/system/script').get()
                now = datetime.now()
                t_str = now.strftime('%b/%d/%Y').lower()
                m_str = now.strftime('%b').lower()
                y_str = now.strftime('%Y')
                for s in scripts:
                    parsed = parse_activation_log(s.get('name',''))
                    if not parsed:
                        continue
                    log_date = parsed['date'].lower()
                    if t_str in log_date:
                        live_data['income_today'] += float(parsed['price'])
                        live_data['sells_today'] += 1
                    if m_str in log_date and y_str in log_date:
                        live_data['income_month'] += float(parsed['price'])
                        live_data['sells_month'] += 1

            # Hotspot logs + active sessions (for users with allow_reports)
            if user_data and user_data.get('allow_reports'):
                try:
                    live_data['hotspot_active'] = api.get_resource('/ip/hotspot/active').get()
                except Exception:
                    live_data['hotspot_active'] = []
                try:
                    # Fetch MikroTik system log filtered by hotspot topics
                    all_logs = api.get_resource('/log').get()
                    hotspot_logs = []
                    for entry in all_logs:
                        topics = (entry.get('topics') or '').lower()
                        msg    = (entry.get('message') or '').lower()
                        if 'hotspot' in topics or 'hotspot' in msg:
                            hotspot_logs.append({
                                'time':    entry.get('time', ''),
                                'topics':  entry.get('topics', ''),
                                'message': entry.get('message', ''),
                            })
                    # Newest first, max 200
                    live_data['hotspot_logs'] = list(reversed(hotspot_logs))[:200]
                except Exception:
                    live_data['hotspot_logs'] = []

            conn.disconnect()
        except Exception:
            pass

    # Activity logs for users with any permission
    user_activity_logs = []
    has_perm = (user_data or {}).get('allow_reports') or (user_data or {}).get('can_generate') or                (user_data or {}).get('allow_user_manage') or (user_data or {}).get('allow_profiles')
    if has_perm:
        user_activity_logs = list(mongo.db.logs.find(
            {'username': (user_data or {}).get('username', '__none__')}
        ).sort('timestamp', -1).limit(50))

    return render_template('user_panel.html', user_data=user_data, data=live_data,
                           selected_router=router, all_routers=routers,
                           user_activity_logs=user_activity_logs,
                           can_generate=user_data.get('can_generate', False),
                           can_reports=user_data.get('allow_reports', False),
                           can_user_manage=user_data.get('allow_user_manage', False),
                           can_profiles=user_data.get('allow_profiles', False),
                           can_port_lock=user_data.get('allow_port_lock', False),
                           can_live_template=user_data.get('allow_live_template', False))




@bp.route('/profile/2fa/setup', methods=['GET', 'POST'])
@login_required
def setup_2fa():
    """TOTP 2FA setup — generate secret, show QR, verify code to activate."""
    from flask import current_app, session
    user_data = mongo.db.users.find_one({'_id': ObjectId(current_user.id)}) or {}
    brand = current_app.config.get('BRAND_NAME', 'MikroMan')

    if request.method == 'POST':
        action = request.form.get('action', '')

        if action == 'generate':
            # Generate new secret, store in session (not DB yet — not confirmed)
            secret = generate_totp_secret()
            session['totp_pending_secret'] = secret
            qr_b64 = get_qr_base64(secret, user_data.get('username', ''), brand)
            return render_template('setup_2fa.html',
                step='verify',
                secret=secret,
                qr_b64=qr_b64,
                manual_code=' '.join([secret[i:i+4] for i in range(0, len(secret), 4)]),
                user_data=user_data,
            )

        if action == 'verify':
            secret = session.get('totp_pending_secret') or request.form.get('secret', '')
            code   = (request.form.get('code') or '').strip()
            if verify_totp(secret, code):
                mongo.db.users.update_one(
                    {'_id': ObjectId(current_user.id)},
                    {'$set': {'totp_secret': secret, 'two_fa_method': 'totp', 'two_fa_enabled': True}}
                )
                session.pop('totp_pending_secret', None)
                flash('Authenticator app enabled! Your account is now protected.', 'success')
                return redirect(url_for('dashboard.profile'))
            else:
                qr_b64 = get_qr_base64(secret, user_data.get('username', ''), brand)
                flash('Wrong code — please try again.', 'danger')
                return render_template('setup_2fa.html',
                    step='verify',
                    secret=secret,
                    qr_b64=qr_b64,
                    manual_code=' '.join([secret[i:i+4] for i in range(0, len(secret), 4)]),
                    user_data=user_data,
                )

        if action == 'disable':
            mongo.db.users.update_one(
                {'_id': ObjectId(current_user.id)},
                {'$set': {'two_fa_method': 'off', 'two_fa_enabled': False, 'totp_secret': None}}
            )
            flash('Two-factor authentication disabled.', 'info')
            return redirect(url_for('dashboard.profile'))

        if action == 'set_email':
            mongo.db.users.update_one(
                {'_id': ObjectId(current_user.id)},
                {'$set': {'two_fa_method': 'email', 'two_fa_enabled': True}}
            )
            flash('Email OTP enabled.', 'success')
            return redirect(url_for('dashboard.profile'))

    return render_template('setup_2fa.html', step='choose', user_data=user_data)


@bp.route('/admin/users')
@login_required
def admin_users():
    """Dedicated full-page user list for admin."""
    from ..models.user import User as UserModel
    user_data = mongo.db.users.find_one({'_id': ObjectId(current_user.id)}) or {}
    if (user_data.get('role') or 'user') != 'admin':
        return redirect(url_for('dashboard.dashboard'))

    users_data = list(mongo.db.users.find({'role': {'$ne': 'admin'}}))
    # Don't check router status synchronously — too slow with many routers/users.
    # Status will be fetched asynchronously via /api/router-status JS fetch.
    for u in users_data:
        for r in u.get('routers', []):
            r['status'] = 'Unknown'

    total_users     = sum(1 for u in users_data if u.get('role') == 'user')
    total_sub_admin = sum(1 for u in users_data if u.get('role') == 'sub-admin')
    total_routers   = sum(len(u.get('routers', []) or []) for u in users_data)

    return render_template('admin_users.html',
        users=users_data,
        total_users=total_users,
        total_sub_admin=total_sub_admin,
        total_routers=total_routers,
    )


@bp.route('/staff')
@login_required
def staff_panel():
    """Legacy /staff URL — redirect to main dashboard (sub-admin is now handled there)."""
    return redirect(url_for('dashboard.dashboard'))


@bp.route('/staff_legacy')
@login_required
def staff_panel_legacy():
    # Reuse the same live data collection used by the normal dashboard,
    # but render a dedicated UI for staff/sub-admin users.
    user_data = mongo.db.users.find_one({'_id': ObjectId(current_user.id)}) or {}
    # SECURITY: only sub-admin (staff) can access Staff Panel
    if (user_data.get('role') or 'user') != 'sub-admin':
        return redirect(url_for('dashboard.dashboard'))

    routers = user_data.get('routers', []) if user_data else []
    selected_id = request.args.get('router_id') or session.get('router_id')
    if request.args.get('router_id'):
        session['router_id'] = request.args.get('router_id')
    router = next((r for r in routers if r.get('id') == selected_id), routers[0] if routers else None)

    live_data = {'active_count': 0, 'total_users': 0, 'system': {}, 'income_today': 0.0, 'income_month': 0.0, 'sells_today': 0, 'sells_month': 0, 'interfaces': []}

    if router:
        try:
            conn, api = _get_pool_api(router)
            live_data['active_count'] = len(api.get_resource('/ip/hotspot/active').get())
            live_data['total_users'] = len(api.get_resource('/ip/hotspot/user').get())
            live_data['interfaces'] = api.get_resource('/interface').get()
            res = api.get_resource('/system/resource').get()
            if res:
                live_data['system'] = res[0]

            if user_data and user_data.get('allow_reports'):
                scripts = api.get_resource('/system/script').get()
                now = datetime.now()
                t_str = now.strftime('%b/%d/%Y').lower()
                m_str = now.strftime('%b').lower()
                y_str = now.strftime('%Y')
                for s in scripts:
                    parsed = parse_activation_log(s.get('name', ''))
                    if not parsed:
                        continue
                    log_date = parsed['date'].lower()
                    if t_str in log_date:
                        live_data['income_today'] += float(parsed['price'])
                        live_data['sells_today'] += 1
                    if m_str in log_date and y_str in log_date:
                        live_data['income_month'] += float(parsed['price'])
                        live_data['sells_month'] += 1

            conn.disconnect()
        except Exception:
            pass

    managed_users = []
    if user_data and user_data.get('allow_user_manage'):
        # staff should manage only users created by them
        managed_users = list(mongo.db.users.find({'role': 'user', 'created_by': str(user_data.get('_id'))}))

    # --- Staff analytics (created_by scope) ---
    now_utc = datetime.now(timezone.utc)
    start_7d = (now_utc - timedelta(days=7)).isoformat()
    month_start_dt = datetime(now_utc.year, now_utc.month, 1)
    month_start = month_start_dt.isoformat()

    # customers
    customers_total = mongo.db.users.count_documents({'role': 'user', 'created_by': str(user_data.get('_id'))})
    customers_new_7d = mongo.db.users.count_documents({'role': 'user', 'created_by': str(user_data.get('_id')), 'created_at': {'$gte': start_7d}})

    # routers (owned by my customers)
    my_customers = list(mongo.db.users.find({'role': 'user', 'created_by': str(user_data.get('_id'))}))
    routers_total = sum(len(u.get('routers', []) or []) for u in my_customers)

    # vouchers & revenue
    def _safe_amount(doc):
        if isinstance(doc.get('amount'), (int, float)):
            return float(doc.get('amount') or 0.0)
        det = (doc.get('details') or '')
        try:
            mq = re.search(r'qty=(\d+)', det)
            mp = re.search(r'price=([0-9\.]+)', det)
            if mq and mp:
                return float(mq.group(1)) * float(mp.group(1))
        except Exception:
            pass
        return 0.0

    staff_logs_7d = list(mongo.db.logs.find({'action': 'generate_vouchers', 'created_by': str(user_data.get('_id')), 'ts': {'$gte': start_7d}}))
    revenue_7d = sum(_safe_amount(d) for d in staff_logs_7d)
    vouchers_7d = sum(int(d.get('qty') or 1) for d in staff_logs_7d)

    staff_logs_m = list(mongo.db.logs.find({'action': 'generate_vouchers', 'created_by': str(user_data.get('_id')), 'ts': {'$gte': month_start}}))
    revenue_month = sum(_safe_amount(d) for d in staff_logs_m)
    vouchers_month = sum(int(d.get('qty') or 1) for d in staff_logs_m)

    # trend: 6 months revenue + new customers
    month_keys, month_labels = _last_n_month_keys(6)
    rev_by_m = {k: 0.0 for k in month_keys}
    new_c_by_m = {k: 0 for k in month_keys}

    trend_docs = list(mongo.db.logs.find({'action': 'generate_vouchers', 'created_by': str(user_data.get('_id'))}))
    for d in trend_docs:
        mk = (d.get('ts') or '')[:7]
        if mk in rev_by_m:
            rev_by_m[mk] += _safe_amount(d)

    # customer trend
    for u in my_customers:
        mk = (u.get('created_at') or '')[:7]
        if mk in new_c_by_m:
            new_c_by_m[mk] += 1

    staff_trend = {
        'labels': month_labels,
        'revenue': [round(rev_by_m[k], 2) for k in month_keys],
        'new_customers': [new_c_by_m[k] for k in month_keys],
    }

    staff_stats = {
        'customers_total': customers_total,
        'customers_new_7d': customers_new_7d,
        'routers_total': routers_total,
        'vouchers_7d': vouchers_7d,
        'revenue_7d': f"{revenue_7d:.2f}",
        'revenue_month': f"{revenue_month:.2f}",
        'vouchers_month': vouchers_month,
    }

    # Fetch profiles for voucher gen
    profiles = []
    if router and user_data.get('can_generate'):
        try:
            conn, api = _get_pool_api(router)
            profiles = [p.get('name') for p in api.get_resource('/ip/hotspot/user/profile').get() if p.get('name')]
            conn.disconnect()
        except Exception:
            pass

    # Users list for staff — only their own customers
    staff_users = list(mongo.db.users.find({'created_by': str(user_data.get('_id'))}))

    # ── Audit logs for sub-admin: own actions + own users' actions ─────────
    staff_id_str = str(user_data.get('_id'))
    my_user_ids  = [staff_id_str] + [str(u['_id']) for u in staff_users]
    my_usernames = [user_data.get('username', '')] + [u.get('username', '') for u in staff_users]

    staff_logs = list(mongo.db.logs.find({
        '$or': [
            {'username': {'$in': [u for u in my_usernames if u]}},
            {'created_by': {'$in': my_user_ids}},
        ]
    }).sort('timestamp', -1).limit(100))
    # ────────────────────────────────────────────────────────────────────────

    return render_template(
        'staff_panel.html',
        user_data=user_data,
        data=live_data,
        selected_router=router,
        all_routers=routers,
        managed_users=managed_users,
        users=staff_users,
        profiles=profiles,
        staff_stats=staff_stats,
        staff_trend=staff_trend,
        staff_logs=staff_logs,
        can_generate=user_data.get('can_generate', False),
        can_user_manage=user_data.get('allow_user_manage', False),
        can_reports=user_data.get('allow_reports', False),
        can_profiles=user_data.get('allow_profiles', False),
        can_profile_edit=user_data.get('allow_profile_edit', False),
    )

# ── Background router status check (admin only) ──────────────────────────────
@bp.route('/api/router-status')
@login_required
def api_router_status():
    """
    SSE stream — each router result is pushed to the client as soon as it's ready.
    Client JS receives individual router updates without waiting for all to finish.
    Query param: ?router_id=X → single router check
    """
    import json as _json
    from concurrent.futures import ThreadPoolExecutor, as_completed
    from flask import Response, stream_with_context

    if current_user.role not in ('admin', 'sub-admin'):
        return Response('data: {"error":"forbidden"}\n\n', status=403, mimetype='text/event-stream')

    target_id = request.args.get('router_id', '').strip()

    if current_user.role == 'admin':
        users_data = list(mongo.db.users.find({'role': {'$ne': 'admin'}}))
    else:
        user_doc = mongo.db.users.find_one({'_id': ObjectId(current_user.id)})
        users_data = [user_doc] if user_doc else []
        managed = list(mongo.db.users.find({'created_by': str(current_user.id)}))
        users_data.extend(managed)

    router_tasks = []
    for u in users_data:
        for r in u.get('routers', []):
            if target_id and r.get('id', '') != target_id:
                continue
            router_tasks.append((r, u.get('username', '?'), str(u.get('_id', ''))))

    def check_one(task):
        r, owner, owner_id = task
        info = {
            'id': r.get('id', ''),
            'name': r.get('name', 'Router'),
            'owner': owner,
            'owner_id': owner_id,
            'ip': r.get('ip', ''),
            'status': 'Offline',
            'identity': '',
            'cpu_load': 0,
            'mem_pct': 0,
            'free_mem': '',
            'uptime': '',
            'version': '',
            'board': '',
            'active_users': 0,
        }
        conn = None
        try:
            # Use direct connection (not pool) — threads don't have Flask session
            conn, api = get_api(r)
            try:
                ident = api.get_resource('/system/identity').get()
                info['identity'] = ident[0].get('name', '') if ident else ''
            except Exception:
                pass
            try:
                res = api.get_resource('/system/resource').get()
                if res:
                    rv = res[0]
                    info['cpu_load'] = int(rv.get('cpu-load', 0) or 0)
                    info['uptime']   = rv.get('uptime', '')
                    info['version']  = rv.get('version', '')
                    info['board']    = rv.get('board-name', '')
                    try:
                        fm = int(rv.get('free-memory', 0) or 0)
                        tm = int(rv.get('total-memory', 1) or 1)
                        info['free_mem'] = f"{fm // 1024 // 1024} MB"
                        info['mem_pct']  = round((1 - fm/tm) * 100) if tm else 0
                    except (ValueError, TypeError, ZeroDivisionError):
                        pass
            except Exception:
                pass
            try:
                active = api.get_resource('/ip/hotspot/active').get()
                info['active_users'] = len(active) if active else 0
            except Exception:
                pass
            info['status'] = 'Online'
        except Exception as exc:
            import logging
            logging.getLogger(__name__).debug(f"Router check failed {r.get('name','?')} ({r.get('ip','')}): {exc}")
        finally:
            if conn:
                try:
                    conn.disconnect()
                except Exception:
                    pass
        return info

    def generate():
        import logging
        _log = logging.getLogger(__name__)
        if not router_tasks:
            _log.info('[RouterStatus SSE] No router tasks found')
            yield 'data: {"done":true,"routers":[]}\n\n'
            return

        _log.info(f'[RouterStatus SSE] Checking {len(router_tasks)} router(s)...')
        all_results = []
        with ThreadPoolExecutor(max_workers=min(len(router_tasks), 10)) as pool:
            futs = {pool.submit(check_one, t): t for t in router_tasks}
            for fut in as_completed(futs):
                try:
                    result = fut.result()
                    all_results.append(result)
                    _log.info(f'[RouterStatus SSE] {result["name"]} ({result["ip"]}) → {result["status"]}')
                    # Push each router result immediately as it completes
                    yield f'data: {_json.dumps({"router": result})}\n\n'
                except Exception as exc:
                    _log.warning(f'[RouterStatus SSE] Future error: {exc}')
        # Final "done" event with full list for carousel rebuild
        online_count = sum(1 for r in all_results if r['status'] == 'Online')
        _log.info(f'[RouterStatus SSE] Done: {len(all_results)} routers, {online_count} online')
        yield f'data: {_json.dumps({"done": True, "routers": all_results})}\n\n'

    return Response(
        stream_with_context(generate()),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no',  # disable nginx buffering
        }
    )


@bp.route('/api/router-ping')
@login_required
def api_router_ping():
    """Quick online/offline check for a single router. Used by user panel status badge."""
    from flask import jsonify
    router_id = request.args.get('router_id', '').strip()
    if not router_id:
        return jsonify({'online': False, 'error': 'No router_id'}), 400

    # Find the router - check ownership
    user_doc = mongo.db.users.find_one({'_id': ObjectId(current_user.id)}) or {}
    role = user_doc.get('role', 'user')

    router = None
    if role == 'admin':
        from bson.objectid import ObjectId as OID
        u = mongo.db.users.find_one({'routers.id': router_id}, {'routers': 1})
        if u:
            router = next((r for r in (u.get('routers') or []) if r.get('id') == router_id), None)
    elif role == 'sub-admin':
        for r in (user_doc.get('routers') or []):
            if r.get('id') == router_id:
                router = r; break
        if not router:
            for u in mongo.db.users.find({'created_by': str(user_doc['_id'])}):
                for r in (u.get('routers') or []):
                    if r.get('id') == router_id:
                        router = r; break
                if router: break
    else:
        for r in (user_doc.get('routers') or []):
            if r.get('id') == router_id:
                router = r; break

    if not router:
        return jsonify({'online': False, 'error': 'Router not found'}), 404

    try:
        conn, api = _get_pool_api(router)
        uptime = ''
        try:
            res = api.get_resource('/system/resource').get()
            if res:
                uptime = res[0].get('uptime', '')
        except Exception:
            pass
        conn.disconnect()
        return jsonify({'online': True, 'uptime': uptime})
    except Exception:
        return jsonify({'online': False, 'uptime': ''})


@bp.route('/api/router-status-json')
@login_required
def api_router_status_json():
    """
    Non-SSE fallback: returns all router statuses as a single JSON response.
    Used as fallback when SSE fails (e.g., proxy buffering, mobile browsers).
    """
    import json as _json
    from concurrent.futures import ThreadPoolExecutor, as_completed

    if current_user.role not in ('admin', 'sub-admin'):
        return jsonify({'ok': False, 'error': 'forbidden'}), 403

    if current_user.role == 'admin':
        users_data = list(mongo.db.users.find({'role': {'$ne': 'admin'}}))
    else:
        user_doc = mongo.db.users.find_one({'_id': ObjectId(current_user.id)})
        users_data = [user_doc] if user_doc else []
        managed = list(mongo.db.users.find({'created_by': str(current_user.id)}))
        users_data.extend(managed)

    router_tasks = []
    for u in users_data:
        for r in u.get('routers', []):
            router_tasks.append((r, u.get('username', '?'), str(u.get('_id', ''))))

    def check_one(task):
        r, owner, owner_id = task
        info = {
            'id': r.get('id', ''),
            'name': r.get('name', 'Router'),
            'owner': owner,
            'owner_id': owner_id,
            'ip': r.get('ip', ''),
            'status': 'Offline',
            'identity': '',
            'cpu_load': 0,
            'mem_pct': 0,
            'free_mem': '',
            'uptime': '',
            'version': '',
            'board': '',
            'active_users': 0,
        }
        conn = None
        try:
            conn, api = get_api(r)
            try:
                ident = api.get_resource('/system/identity').get()
                info['identity'] = ident[0].get('name', '') if ident else ''
            except Exception:
                pass
            try:
                res = api.get_resource('/system/resource').get()
                if res:
                    rv = res[0]
                    info['cpu_load'] = int(rv.get('cpu-load', 0) or 0)
                    info['uptime']   = rv.get('uptime', '')
                    info['version']  = rv.get('version', '')
                    info['board']    = rv.get('board-name', '')
                    try:
                        fm = int(rv.get('free-memory', 0) or 0)
                        tm = int(rv.get('total-memory', 1) or 1)
                        info['free_mem'] = f"{fm // 1024 // 1024} MB"
                        info['mem_pct']  = round((1 - fm/tm) * 100) if tm else 0
                    except (ValueError, TypeError, ZeroDivisionError):
                        pass
            except Exception:
                pass
            try:
                active = api.get_resource('/ip/hotspot/active').get()
                info['active_users'] = len(active) if active else 0
            except Exception:
                pass
            info['status'] = 'Online'
        except Exception:
            pass
        finally:
            if conn:
                try:
                    conn.disconnect()
                except Exception:
                    pass
        return info

    results = []
    if router_tasks:
        with ThreadPoolExecutor(max_workers=min(len(router_tasks), 10)) as pool:
            futs = {pool.submit(check_one, t): t for t in router_tasks}
            for fut in as_completed(futs):
                try:
                    results.append(fut.result())
                except Exception:
                    pass

    return jsonify({'ok': True, 'routers': results})


@bp.route('/api/pool-stats')
@login_required
def api_pool_stats():
    """Return connection pool statistics (admin only)."""
    from ..utils.permissions import is_admin
    if not is_admin():
        return jsonify({'error': 'forbidden'}), 403
    return jsonify(router_pool.get_pool_stats())


# ─── Self-service Router Add (registered users) ──────────────
@bp.route('/my-router', methods=['GET'])
@login_required
def my_router():
    """Page where user can add their own router."""
    user_data = mongo.db.users.find_one({'_id': ObjectId(current_user.id)}) or {}

    if user_data.get('role') in ('admin', 'sub-admin'):
        return redirect(url_for('admin.admin_config'))

    user_routers = user_data.get('routers', []) or []

    return render_template('add_my_router.html',
                           user_routers=user_routers,
                           can_add_router=True,
                           max_routers_reached=False,
                           max_routers=0)


@bp.route('/my-router/save', methods=['POST'])
@login_required
def save_my_router():
    """Save user's own router (self-service)."""
    import uuid
    user_data = mongo.db.users.find_one({'_id': ObjectId(current_user.id)}) or {}

    if user_data.get('role') in ('admin', 'sub-admin'):
        flash('Use admin config to manage routers.', 'info')
        return redirect(url_for('admin.admin_config'))

    from ..utils.crypto import encrypt_text

    user_routers = user_data.get('routers', []) or []

    r_name = (request.form.get('r_name') or 'Router').strip()
    r_ip = (request.form.get('r_ip') or '').strip()
    r_port = (request.form.get('r_port') or '8728').strip()
    r_user = (request.form.get('r_user') or '').strip()
    r_pass = (request.form.get('r_pass') or '').strip()

    if not r_ip or not r_user:
        flash('Router IP and username are required.', 'danger')
        return redirect(url_for('dashboard.my_router'))

    # Validate port
    try:
        r_port_int = int(r_port)
        if r_port_int < 1 or r_port_int > 65535:
            raise ValueError
    except ValueError:
        flash('Invalid API port.', 'danger')
        return redirect(url_for('dashboard.my_router'))

    router = {
        'id': uuid.uuid4().hex[:8],
        'name': r_name,
        'ip': r_ip,
        'api_port': r_port_int,
        'api_user': r_user,
        'api_pass_enc': encrypt_text(r_pass),
        'dns_name': 'login.net',
        'currency': 'AED',
        'self_added': True,
    }

    mongo.db.users.update_one(
        {'_id': ObjectId(current_user.id)},
        {'$push': {'routers': router}}
    )
    flash(f'Router "{r_name}" connected successfully!', 'success')
    return redirect(url_for('dashboard.dashboard'))


@bp.route('/my-router/edit', methods=['POST'])
@login_required
def edit_my_router():
    """Edit user's own router (self-service)."""
    from ..utils.crypto import encrypt_text

    user_data = mongo.db.users.find_one({'_id': ObjectId(current_user.id)}) or {}
    if user_data.get('role') in ('admin', 'sub-admin'):
        flash('Use admin config to manage routers.', 'info')
        return redirect(url_for('admin.admin_config'))

    r_id = (request.form.get('r_id') or '').strip()
    r_name = (request.form.get('r_name') or 'Router').strip()
    r_ip = (request.form.get('r_ip') or '').strip()
    r_user = (request.form.get('r_user') or '').strip()
    r_pass = (request.form.get('r_pass') or '').strip()

    if not r_id:
        flash('Router ID missing', 'danger')
        return redirect(url_for('dashboard.my_router'))

    fields = {
        'routers.$.name': r_name,
        'routers.$.ip': r_ip,
        'routers.$.api_user': r_user,
    }
    if r_pass:
        fields['routers.$.api_pass_enc'] = encrypt_text(r_pass)

    result = mongo.db.users.update_one(
        {'_id': ObjectId(current_user.id), 'routers.id': r_id},
        {'$set': fields}
    )
    if result.modified_count:
        flash(f'Router "{r_name}" updated successfully!', 'success')
    else:
        flash('Router not found or no changes made.', 'warning')
    return redirect(url_for('dashboard.my_router'))


@bp.route('/my-router/delete/<r_id>')
@login_required
def delete_my_router(r_id):
    """Delete user's own router (self-service)."""
    user_data = mongo.db.users.find_one({'_id': ObjectId(current_user.id)}) or {}
    if user_data.get('role') in ('admin', 'sub-admin'):
        flash('Use admin config to manage routers.', 'info')
        return redirect(url_for('admin.admin_config'))

    mongo.db.users.update_one(
        {'_id': ObjectId(current_user.id)},
        {'$pull': {'routers': {'id': r_id}}}
    )
    flash('Router deleted successfully.', 'success')
    return redirect(url_for('dashboard.my_router'))
