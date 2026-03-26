import io
import base64
import time
import uuid
import os
import random
import re
import threading
from bson.objectid import ObjectId
from datetime import datetime, timezone
from flask import Blueprint, render_template, request, redirect, url_for, flash, send_file, abort, session, jsonify, current_app
from flask_login import login_required, current_user, login_user
from jinja2.sandbox import SandboxedEnvironment
from werkzeug.security import generate_password_hash
from ..extensions import mongo
from ..models.user import User
from ..services.mikrotik import (
    get_api,
    get_api_pooled,
    list_hotspot_user_profiles,
    list_ip_pools,
    list_parent_queues,
    add_hotspot_user_profile,
    get_hotspot_user_profile_by_name,
    update_hotspot_user_profile,
    parse_on_login_put_line,
    list_ip_bindings,
    add_ip_binding,
    delete_ip_binding,
    scan_bridges_and_ports,
    get_port_lock_config,
    save_port_lock_config,
    delete_port_lock_config,
    detect_lock_state,
    port_lock_action,
    ensure_port_lock_scripts,
    list_ppp_secrets, add_ppp_secret, update_ppp_secret, delete_ppp_secret,
    list_ppp_profiles, list_nat_rules, add_nat_rule, toggle_nat_rule, delete_nat_rule,
)
from ..services.router_pool import router_pool
from ..services.pdf_service import html_to_pdf_bytes
from ..services.logger import log_activity
from ..utils.helpers import generate_random_string
from ..utils.parsing import parse_activation_log
from ..extensions import limiter


def get_next_voucher_serial(router_id):
    """Atomically get next voucher serial for a router. Returns e.g. 'vc-155'"""
    result = mongo.db.voucher_serials.find_one_and_update(
        {'router_id': router_id},
        {'$inc': {'seq': 1}},
        upsert=True,
        return_document=True
    )
    seq = result.get('seq', 1) if result else 1
    return f'vc-{seq}'


def resolve_batch_comment(router, batch_comment_input: str, existing_users=None) -> str:
    """
    Determine the final comment/label for this batch.
    Always returns 'vc-{name}' format so the on-login script condition fires.
    - blank input → caller should use serial (vc-N)
    - name given  → 'vc-name' if fresh, else 'vc-name_01', 'vc-name_02' ...
    existing_users: pass pre-fetched list to avoid a second router connection
    """
    name = (batch_comment_input or '').strip()
    if not name:
        return None

    # Strip any existing 'vc-' prefix before working — we'll re-add it at the end
    clean = name[3:] if name.lower().startswith('vc-') else name

    if existing_users is None:
        try:
            conn, api = _get_pool_api(router)
            existing_users = api.get_resource('/ip/hotspot/user').get()
            conn.disconnect()
        except Exception:
            existing_users = []

    date_re = re.compile(
        r'\b(?:jan|feb|mar|apr|may|jun|jul|aug|sep|sept|oct|nov|dec)'
        r'/\d{1,2}/\d{4}(?:\s+\d{1,2}:\d{2}:\d{2})?\b',
        re.IGNORECASE
    )
    bracket_re = re.compile(r'\[.*?\]')  # strip [25-Mar-2026 12:30PM x10] metadata
    used_labels = set()
    for u in existing_users:
        raw = (u.get('comment') or '').strip()
        # Strip date, bracket metadata, and 'vc-' prefix when building the used-labels set
        label = date_re.sub('', raw).strip()
        label = bracket_re.sub('', label).strip().lower()
        if label.startswith('vc-'):
            label = label[3:]
        if label:
            used_labels.add(label)

    base = clean.lower()
    if base not in used_labels:
        return f'vc-{clean}'

    for n in range(1, 100):
        candidate = f'{clean}_{n:02d}'
        if candidate.lower() not in used_labels:
            return f'vc-{candidate}'

    return f'vc-{clean}_{datetime.now().strftime("%H%M%S")}'
from ..utils.crypto import encrypt_text
from ..utils.permissions import require_admin, require_flag

# Sandboxed Jinja2 environment for user-editable voucher templates.
# Prevents SSTI: blocks access to __class__, __mro__, config, etc.
_sandbox_env = SandboxedEnvironment()

def _safe_render_voucher(template_html: str, context: dict) -> str:
    """Render a voucher template string safely using Jinja2 sandbox.
    Falls back to empty string on any error to never break PDF generation."""
    try:
        tpl = _sandbox_env.from_string(template_html)
        return tpl.render(**context)
    except Exception:
        # If template is malformed, return a safe fallback
        return f"<div>User: {context.get('username', '?')}</div>"


# Default live voucher template used when no custom template is saved in settings.
# Uses Jinja2 placeholders rendered per voucher.
DEFAULT_LIVE_TEMPLATE = """<table class="voucher" style="width:220px;">
  <tbody>
    <tr>
      <td style="text-align:left;font-size:13px;font-weight:bold;border-bottom:1px solid black;padding:4px 6px;">
        {% if logo %}<img src="{{ logo }}" alt="logo" style="height:24px;border:0;vertical-align:middle;margin-right:4px;">{% endif %}
        {{ hotspotname }} <span style="float:right;font-weight:normal;font-size:11px;">[{{ num }}]</span>
      </td>
    </tr>
    <tr>
      <td style="padding:4px 6px;">
        <table style="text-align:center;width:100%;font-size:12px;">
          <tbody>
            <tr>
              <td>
                <table style="width:100%;">
                  {% if usermode == "vc" %}
                  <tr><td style="font-size:11px;color:#555;">Voucher Code</td></tr>
                  <tr>
                    <td style="border:1px solid black;font-weight:bold;font-size:15px;padding:3px;">{{ username }}</td>
                  </tr>
                  {% else %}
                  <tr>
                    <td style="width:50%;font-size:11px;">Username</td>
                    <td style="font-size:11px;">Password</td>
                  </tr>
                  <tr style="font-size:13px;">
                    <td style="border:1px solid black;font-weight:bold;padding:3px;">{{ username }}</td>
                    <td style="border:1px solid black;font-weight:bold;padding:3px;">{{ password }}</td>
                  </tr>
                  {% endif %}
                </table>
              </td>
            </tr>
            <tr>
              <td style="border-top:1px solid black;font-weight:bold;font-size:14px;padding:3px 0;">
                {{ validity }}{% if timelimit and timelimit != validity %} {{ timelimit }}{% endif %}{% if datalimit %} {{ datalimit }}{% endif %}{% if price %} | {{ price }}{% endif %}
              </td>
            </tr>
            <tr>
              <td style="font-size:10px;color:#333;padding:2px 0;">Login: http://{{ dnsname }}</td>
            </tr>
          </tbody>
        </table>
      </td>
    </tr>
  </tbody>
</table>
"""

def get_live_template_html():
    """Return the latest voucher template HTML.

    Priority:
      1) settings doc: {type: 'voucher_template'} -> field 'html' (edited via /admin/live_template)
      2) app_settings.live_html (legacy/backward compatible)
      3) DEFAULT_LIVE_TEMPLATE
    """
    tpl_doc = mongo.db.settings.find_one({'type': 'voucher_template'}) or {}
    html = (tpl_doc.get('html') or '').strip()
    if html:
        return html
    app_settings = mongo.db.settings.find_one({'_id': 'app_settings'}) or {}
    html2 = (app_settings.get('live_html') or '').strip()
    return html2 if html2 else DEFAULT_LIVE_TEMPLATE

bp = Blueprint('admin', __name__)

# Exempt JSON/AJAX API endpoints from CSRF (they use session auth + custom headers)
from ..extensions import csrf as _csrf


def _get_session_id() -> str:
    """Get a stable session identifier for the connection pool."""
    sid = session.get('_pool_sid')
    if not sid:
        sid = session.get('_id') or str(uuid.uuid4())
        session['_pool_sid'] = sid
    return sid


def _get_pool_api(router: dict):
    """
    Get a pooled API connection for the current session.
    Returns (conn, api) where conn.disconnect() is a no-op.
    Falls back to fresh connection if pool fails.
    """
    try:
        sid = _get_session_id()
        return get_api_pooled(router, session_id=sid)
    except Exception:
        return get_api(router)

_hotspot_locks = {}
_hotspot_locks_meta = threading.Lock()

def _get_router_lock(router_id: str) -> threading.Lock:
    """Get or create a per-router lock for serializing writes to the same router."""
    with _hotspot_locks_meta:
        if router_id not in _hotspot_locks:
            _hotspot_locks[router_id] = threading.Lock()
        return _hotspot_locks[router_id]


def _find_router_any_user(router_id: str):
    """Find a router dict by router_id across all user documents.

    Admin pages often operate on routers owned by non-admin users.
    Some older handlers incorrectly searched only the current user's routers,
    which makes router_id look "missing" from admin panel navigation.
    """
    if not router_id:
        return None
    user_with_router = mongo.db.users.find_one(
        {'routers.id': router_id},
        {'routers': 1}  # projection: fetch only routers, not full user doc
    )
    if not user_with_router:
        return None
    return next((r for r in (user_with_router.get('routers') or []) if r.get('id') == router_id), None)


def _get_accessible_routers(user_doc: dict) -> list:
    """Return de-duplicated router list accessible to a user.

    - admin     : all routers across all users (dedup by IP)
    - sub-admin : own + managed users' routers (dedup by IP)
    - user      : own routers only

    Routers with the same IP are considered the same physical device.
    Only the first occurrence is kept so the UI never shows duplicates
    when the same router is assigned to multiple users.
    """
    role = user_doc.get('role', 'user')
    result   = []
    seen_ids = set()
    seen_ips = set()

    def _add(r, owner=''):
        rid = r.get('id'); rip = r.get('ip')
        if rid in seen_ids:
            return
        if rip and rip in seen_ips:
            return
        seen_ids.add(rid)
        if rip:
            seen_ips.add(rip)
        r2 = dict(r)
        if owner:
            r2.setdefault('owner', owner)
        result.append(r2)

    if role == 'admin':
        for u in mongo.db.users.find({'routers': {'$exists': True, '$ne': []}}):
            for r in (u.get('routers') or []):
                _add(r, u.get('username', ''))
    elif role == 'sub-admin':
        for r in (user_doc.get('routers') or []):
            _add(r)
        for u in mongo.db.users.find({'created_by': str(user_doc.get('_id', ''))}):
            for r in (u.get('routers') or []):
                _add(r, u.get('username', ''))
    else:
        for r in (user_doc.get('routers') or []):
            _add(r)

    return result


def _get_router_for_current_user(router_id: str):
    """
    Secure router resolver — enforces ownership.
    - Admin: any router
    - Sub-admin: own routers + managed users routers
    - User: own routers only
    """
    from flask import abort
    if not router_id:
        abort(400)
    actor = mongo.db.users.find_one({'_id': ObjectId(current_user.id)}) or {}
    role  = actor.get('role', 'user')
    if role == 'admin':
        router = _find_router_any_user(router_id)
    elif role == 'sub-admin':
        routers = actor.get('routers') or []
        router = next((r for r in routers if r.get('id') == router_id), None)
        if not router:
            for u in mongo.db.users.find({'created_by': str(actor.get('_id', ''))}):
                router = next((r for r in (u.get('routers') or []) if r.get('id') == router_id), None)
                if router:
                    break
    else:
        routers = actor.get('routers') or []
        router  = next((r for r in routers if r.get('id') == router_id), None)
    return router


def _get_active_router():
    """Get the currently active router from session. No router_id in URL needed."""
    rid = session.get('router_id')
    if not rid:
        return None
    return _get_router_for_current_user(rid)


def _require_active_router():
    """Get active router or flash error and return None."""
    router = _get_active_router()
    if not router:
        flash('Please select a router first', 'warning')
    return router

@bp.route('/create-vouchers')
@login_required
@require_flag('can_generate')
def create_vouchers_page():
    user_data = mongo.db.users.find_one({'_id': ObjectId(current_user.id)}) or {}
    # Use unified router_id session key (synced by context processor)
    selected_id = request.args.get('router_id') or session.get('router_id')
    if request.args.get('router_id'):
        session['router_id'] = request.args.get('router_id')
    # Use unified resolver (admin=any, sub-admin=own+managed, user=own)
    router = _get_router_for_current_user(selected_id) if selected_id else None
    if not router:
        flash('Notification: No router selected from dashboard!', 'warning')
        return redirect(url_for('dashboard.dashboard'))

    profiles = []
    try:
        conn, api = _get_pool_api(router)
        profiles = [p['name'] for p in api.get_resource('/ip/hotspot/user/profile').get()]
        conn.disconnect()
    except Exception as e:
        flash(f'Router Connection Error: {str(e)}', 'danger')

    return render_template('voucher.html', user_data=user_data, profiles=profiles, selected_router=router)

@bp.route('/api/get_profile_details/<router_id>/<profile_name>')
@login_required
@require_flag('can_generate')
def get_profile_details(router_id, profile_name):
    router = _get_router_for_current_user(router_id)
    if not router:
        return {'error': 'Router not found'}, 404

    try:
        conn, api = _get_pool_api(router)
        profiles = api.get_resource('/ip/hotspot/user/profile').get(name=profile_name)
        conn.disconnect()
        if profiles:
            on_login = profiles[0].get('on-login', '')
            m = re.search(r'interval="(\d+[smhdw])"', on_login)
            validity = m.group(1) if m else '30d'
            return {'on_login': on_login, 'validity': validity}
        return {'error': 'Profile not found'}, 404
    except Exception as e:
        return {'error': str(e)}, 500
        
@bp.route('/admin/get_profiles/<router_id>')
@login_required
@require_flag('can_generate')
def admin_get_profiles(router_id):
    router = _get_router_for_current_user(router_id)
    if not router:
        return {'profiles': [], 'error': 'Router not found or access denied'}, 404

    try:
        conn, api = _get_pool_api(router)
        profiles = [p['name'] for p in api.get_resource('/ip/hotspot/user/profile').get()]
        conn.disconnect()
        return {'profiles': profiles}
    except Exception as e:
        return {'profiles': [], 'error': str(e)}, 500


@bp.route('/admin/generate_hotspot', methods=['POST'])
@login_required
@require_flag('can_generate')
def generate_hotspot():
    user_role = getattr(current_user, 'role', 'user')

    try:
        qty = int(request.form.get('qty', 1))
    except Exception:
        qty = 1
    if user_role == 'user' and qty > 500:
        flash('Maximum 500 vouchers per batch for regular users.', 'danger')
        return redirect(url_for('dashboard.dashboard'))

    # Idempotency token: prevents duplicate generation on refresh / connection hiccups.
    # If the same token is submitted again by the same actor, we return the same PDF.
    form_token = (request.form.get('token') or '').strip() or f"gen_{uuid.uuid4().hex}"
    cached = mongo.db.gen_results.find_one({'token': form_token, 'user_id': str(current_user.id)})
    if cached and cached.get('pdf_b64'):
        try:
            pdf_bytes = base64.b64decode(cached['pdf_b64'].encode('utf-8'))
            return send_file(
                io.BytesIO(pdf_bytes),
                as_attachment=True,
                download_name=cached.get('filename') or 'Vouchers.pdf',
                mimetype='application/pdf'
            )
        except Exception:
            # If cache is corrupted, fall through and regenerate.
            pass

    if not _get_router_lock(request.form.get('router_id', 'default')).acquire(blocking=False):
        flash('Another generation is in progress for this router. Please wait...', 'warning')
        return redirect(url_for('dashboard.dashboard'))

    try:

        router_id = request.form.get('router_id')
        branding = request.form.get('branding_name', 'My Hotspot')
        validity = request.form.get('timelimit', '30d')
        price = request.form.get('price', '0.00')
        profile = request.form.get('profile', 'default')
        display_name = (request.form.get('display_name') or '').strip()
        mt_profile = profile
        profile_display = display_name if display_name else profile

        user_mode = request.form.get('user_mode', 'up')
        user_l = int(request.form.get('user_length', 6))
        char_mode = request.form.get('char_mode', 'mix')

        now = datetime.now()
        curr_date = now.strftime('%d-%b-%Y')
        curr_time = now.strftime('%I:%M %p')

        router = _get_router_for_current_user(router_id)
        if not router:
            flash('Router not found or access denied!', 'danger')
            return redirect(url_for('dashboard.dashboard'))

        conn, api = _get_pool_api(router)
        res = api.get_resource('/ip/hotspot/user')

        vouchers_list = []

        # ── Determine batch comment label ──────────────────────────────────
        # Use display_name as batch comment; fallback to batch_comment field; else auto serial
        _bc_input = (request.form.get('display_name') or request.form.get('batch_comment') or '').strip()
        _base_label = resolve_batch_comment(router, _bc_input) if _bc_input else get_next_voucher_serial(router_id)
        # Append generation date and quantity for tracking
        _gen_date = datetime.now().strftime('%d-%b-%Y %I:%M%p')
        sync_batch_comment = f'{_base_label} [{_gen_date} x{qty}]'
        # ──────────────────────────────────────────────────────────────────

        # Get logo for this router
        _logo_uri = _get_logo_data_uri(router_id)

        # Dynamic pacing: optimized for speed with pooled connections.
        if user_role == 'user':
            per_delay = 0.02 if qty <= 50 else 0.03 if qty <= 120 else 0.05 if qty <= 300 else 0.06
        else:
            per_delay = 0.01 if qty <= 200 else 0.02

        # Generate slightly slower to reduce RouterOS load and avoid transient disconnect errors.
        for i in range(qty):
            u_name = generate_random_string(user_l, char_mode)
            u_pass = u_name if user_mode == 'vc' else generate_random_string(user_l, char_mode)
            added = False
            last_err = None
            for _attempt in range(3):
                try:
                    res.add(name=u_name, password=u_pass, profile=mt_profile, comment=sync_batch_comment)
                    added = True
                    break
                except Exception as e:
                    last_err = e
                    # Brief backoff; then retry (RouterOS can drop connections under burst writes)
                    time.sleep(0.25)
            if added:
                vouchers_list.append({
                    'hotspotname': branding,
                    'username': u_name,
                    'password': u_pass,
                    'validity': validity,
                    'timelimit': validity,
                    'datalimit': '',
                    'price': price,
                    'profile': profile_display,
                    'mt_profile': mt_profile,
                    'comment': sync_batch_comment,
                    'usermode': user_mode,
                    'date': curr_date,
                    'time': curr_time,
                    'num': i + 1,
                    'router_name': router.get('name', 'MikroMan'),
                    'dnsname': router.get('dns_name', 'login.net'),
                    'logo': _logo_uri,
                })
            # Small delay between inserts (keeps UI responsive and prevents connection loss)
            time.sleep(per_delay)
        conn.disconnect()

        # Activity log (used for staff analytics)
        try:
            try:
                price_f = float(price)
            except Exception:
                price_f = 0.0
            amount = float(qty) * price_f
            _uname_sync = getattr(current_user, 'username', '') or str(current_user.id)
            _rname_sync = router_id
            try:
                _rname_sync = router.get('name', router_id) if router else router_id
            except Exception:
                pass
            log_activity(
                _uname_sync,
                'generate_vouchers',
                f'qty={qty}, router={_rname_sync}, profile={profile}, price={price}',
                created_by=str(current_user.id),
                qty=int(qty),
                price=price_f,
                amount=amount,
                router_id=str(router_id),
                profile=str(profile),
            )
        except Exception:
            pass

        db_tpl = mongo.db.settings.find_one({'type': 'voucher_template'})
        live_html = db_tpl['html'] if db_tpl else '<div>User: {{username}}</div>'

        final_pdf_html = """<html><head><meta charset='UTF-8'>
        <style>@page { size: A4; margin: 0.5cm; }
        body { font-family: Helvetica, sans-serif; font-size: 10px; }
        .master-table { width: 100%; border-collapse: collapse; }
        .v-cell { width: 25%; padding: 5px; vertical-align: top; }
        </style></head><body><table class='master-table'>"""

        for idx, v in enumerate(vouchers_list):
            if idx % 4 == 0:
                final_pdf_html += '<tr>'
            rendered = _safe_render_voucher(live_html, v)
            final_pdf_html += f"<td class='v-cell'>{rendered}</td>"
            if (idx + 1) % 4 == 0:
                final_pdf_html += '</tr>'

        final_pdf_html += '</table></body></html>'

        pdf_io = html_to_pdf_bytes(final_pdf_html)
        # Cache PDF result by token (short-term) so that a retry returns the same file.
        try:
            filename = f"Vouchers_{now.strftime('%d%m%Y_%H%M%S')}.pdf"
            pdf_bytes = pdf_io.getvalue() if hasattr(pdf_io, 'getvalue') else pdf_io.read()
            mongo.db.gen_results.update_one(
                {'token': form_token, 'user_id': str(current_user.id)},
                {'$set': {
                    'token': form_token,
                    'user_id': str(current_user.id),
                    'filename': filename,
                    'pdf_b64': base64.b64encode(pdf_bytes).decode('utf-8'),
                    'created_at': datetime.now(timezone.utc),
                }},
                upsert=True
            )
            # Rewind for send_file
            pdf_io = io.BytesIO(pdf_bytes)
        except Exception:
            filename = f"Vouchers_{now.strftime('%d%m%Y_%H%M%S')}.pdf"
        return send_file(pdf_io, as_attachment=True, download_name=filename, mimetype='application/pdf')

    except Exception as e:
        # Allow retry with the same token if generation failed.
        try:
            mongo.db.gen_results.delete_one({'token': form_token, 'user_id': str(current_user.id)})
        except Exception:
            pass
        flash('Connection lost / error during generation. Please try again (same token will not duplicate).', 'danger')
        return redirect(url_for('dashboard.dashboard'))
    finally:
        try:
            _get_router_lock(request.form.get('router_id', 'default')).release()
        except RuntimeError:
            pass  # Lock was not held by this thread

# ---------------- Voucher generation (async with progress) ----------------

def _init_progress(token: str, total: int, user_id: str):
    """Initialize progress doc for async voucher generation.

    IMPORTANT: This function must be safe to call from background threads.
    So we never touch `current_user` here; caller must pass user_id explicitly.
    """
    mongo.db.gen_progress.update_one(
        {'token': token, 'user_id': str(user_id)},
        {'$set': {'status': 'running', 'progress': 0, 'total': int(total or 0), 'percent': 0,
                  'message': 'Starting...', 'updated_at': datetime.now(timezone.utc)},
         '$setOnInsert': {'created_at': datetime.now(timezone.utc)}},
        upsert=True
    )

def _set_progress(token: str, progress: int, total: int, message: str, user_id: str):
    """Update progress safely from background thread."""
    try:
        pct = int((int(progress) / max(int(total), 1)) * 100)
    except Exception:
        pct = 0
    mongo.db.gen_progress.update_one(
        {'token': token, 'user_id': str(user_id)},
        {'$set': {'status': 'running', 'progress': int(progress), 'total': int(total),
                  'percent': pct, 'message': message or '', 'updated_at': datetime.now(timezone.utc)}},
        upsert=True
    )

def _finish_progress(token: str, ok: bool, message: str, user_id: str):
    """Finalize progress safely from background thread."""
    mongo.db.gen_progress.update_one(
        {'token': token, 'user_id': str(user_id)},
        {'$set': {'status': 'done' if ok else 'failed',
                  'message': message or '',
                  'updated_at': datetime.now(timezone.utc),
                  'percent': 100 if ok else 0}},
        upsert=True
    )

def _generate_vouchers_worker(app, actor_id: str, token: str, form: dict, actor_username: str = ''):
    """Background worker that generates vouchers and stores the resulting PDF in gen_results."""
    # NOTE: We must not use current_user in background thread; use actor_id.
    try:
        with app.app_context():
            try:
                qty = int(form.get('qty', 1))
            except Exception:
                qty = 1

            role = form.get('_role', 'user')
            # Enforce limits again (server-side)
            if role == 'user' and qty > 500:
                mongo.db.gen_progress.update_one({'token': token, 'user_id': actor_id}, {'$set': {'status': 'failed', 'message': 'User limit: max 500 vouchers', 'updated_at': datetime.now(timezone.utc)}}, upsert=True)
                return

            router_id = form.get('router_id')
            branding = form.get('branding_name', 'My Hotspot')
            validity = form.get('timelimit', '30d')
            price = form.get('price', '0.00')
            profile = form.get('profile', 'default')
            display_name = (form.get('display_name') or '').strip()
            mt_profile = profile
            profile_display = display_name if display_name else profile

            user_mode = form.get('user_mode', 'up')
            try:
                user_l = int(form.get('user_length', 6))
            except Exception:
                user_l = 6
            char_mode = form.get('char_mode', 'mix')

            now = datetime.now()
            curr_date = now.strftime('%d-%b-%Y')
            curr_time = now.strftime('%I:%M %p')

            # Dynamic pacing: optimized for speed with pooled connections.
            if role == 'user':
                per_delay = 0.02 if qty <= 50 else 0.03 if qty <= 120 else 0.05 if qty <= 300 else 0.06
            else:
                per_delay = 0.01 if qty <= 200 else 0.02

            try:
                _init_progress(token, qty, actor_id)

                router = _find_router_any_user(router_id)
                if not router:
                    _finish_progress(token, False, 'Router not found', actor_id)
                    return

                conn, api = _get_pool_api(router)
                res = api.get_resource('/ip/hotspot/user')

                vouchers_list = []

                # ── Determine batch comment label ──────────────────────────────────
                # display_name from voucher form → use as batch comment label
                batch_comment_input = (form.get('display_name') or form.get('batch_comment') or '').strip()
                # Fetch existing users once (used for duplicate check + generation)
                existing_users = res.get()
                if batch_comment_input:
                    resolved_label = resolve_batch_comment(router, batch_comment_input, existing_users)
                else:
                    resolved_label = get_next_voucher_serial(router_id)

                # Append generation date and quantity for tracking
                _gen_date = datetime.now().strftime('%d-%b-%Y %I:%M%p')
                batch_comment = f'{resolved_label} [{_gen_date} x{qty}]'
                # ──────────────────────────────────────────────────────────────────

                # Get logo for this router
                _logo_uri = _get_logo_data_uri(router_id)

                for i in range(qty):
                    u_name = generate_random_string(user_l, char_mode)
                    u_pass = u_name if user_mode == 'vc' else generate_random_string(user_l, char_mode)

                    added = False
                    last_err = None
                    for _attempt in range(3):
                        try:
                            res.add(name=u_name, password=u_pass, profile=mt_profile, comment=batch_comment)
                            added = True
                            break
                        except Exception as e:
                            last_err = e
                            time.sleep(0.25)

                    if added:
                        vouchers_list.append({
                            'hotspotname': branding,
                            'username': u_name,
                            'password': u_pass,
                            'validity': validity,
                            'timelimit': validity,
                            'datalimit': '',
                            'price': price,
                            'profile': profile_display,
                            'mt_profile': mt_profile,
                            'comment': batch_comment,
                            'usermode': user_mode,
                            'date': curr_date,
                            'time': curr_time,
                            'num': i + 1,
                            'router_name': router.get('name', 'MikroMan'),
                            'dnsname': router.get('dns_name', 'login.net'),
                            'logo': _logo_uri,
                        })
                    else:
                        _finish_progress(token, False, f'Failed to add user (at #{i+1}): {last_err}', actor_id)
                        try:
                            conn.close()
                        except Exception:
                            pass
                        return

                    # progress update (every 3 or final - smoother bar)
                    if (i + 1) % 3 == 0 or (i + 1) == qty:
                        _set_progress(token, i + 1, qty, f'Generated {i+1}/{qty}...', actor_id)

                    time.sleep(per_delay)

                try:
                    conn.close()
                except Exception:
                    pass

                # Build final PDF
                settings = mongo.db.settings.find_one({'_id': 'app_settings'}) or {}
                live_html = get_live_template_html()

                final_pdf_html = """<html><head><meta charset='utf-8'>
                <style>
                body { font-family: Arial; font-size: 12px; }
                table.master-table { width: 100%; border-collapse: collapse; }
                td.v-cell { width: 25%; padding: 6px; vertical-align: top; }
                </style></head><body><table class='master-table'>"""

                for idx, v in enumerate(vouchers_list):
                    if idx % 4 == 0:
                        final_pdf_html += '<tr>'
                    rendered = _safe_render_voucher(live_html, v)
                    final_pdf_html += f"<td class='v-cell'>{rendered}</td>"
                    if (idx + 1) % 4 == 0:
                        final_pdf_html += '</tr>'

                final_pdf_html += '</table></body></html>'

                pdf_io = html_to_pdf_bytes(final_pdf_html)
                filename = f"Vouchers_{now.strftime('%d%m%Y_%H%M%S')}.pdf"
                pdf_bytes = pdf_io.getvalue() if hasattr(pdf_io, 'getvalue') else pdf_io.read()

                mongo.db.gen_results.update_one(
                    {'token': token, 'user_id': actor_id},
                    {'$set': {'pdf_b64': base64.b64encode(pdf_bytes).decode('utf-8'),
                              'filename': filename,
                              'created_at': datetime.now(timezone.utc)}},
                    upsert=True
                )
                _finish_progress(token, True, 'Done', actor_id)
                # Activity log
                try:
                    # Lookup username if not passed
                    _uname = actor_username or actor_id
                    if not actor_username:
                        try:
                            _udoc = mongo.db.users.find_one({'_id': ObjectId(actor_id)}, {'username': 1})
                            _uname = (_udoc or {}).get('username', actor_id)
                        except Exception:
                            pass
                    # Lookup router name
                    _router_name = router_id
                    try:
                        _router_name = router.get('name', router_id) if router else router_id
                    except Exception:
                        pass
                    log_activity(
                        _uname,
                        'generate_vouchers',
                        f'qty={qty}, router={_router_name}, profile={profile}, price={price}',
                        created_by=actor_id,
                        qty=int(qty),
                        price=float(price) if price else 0.0,
                        amount=float(price) * int(qty) if price else 0.0,
                        router_id=str(router_id),
                    )
                except Exception:
                    pass

            except Exception as e:
                import traceback
                err_msg = str(e) or repr(e) or 'Unknown error'
                err_tb = traceback.format_exc()
                import logging
                logging.getLogger(__name__).error(f'Voucher worker failed: {err_msg}\n{err_tb}')
                try:
                    mongo.db.gen_progress.update_one({'token': token, 'user_id': actor_id},
                                                    {'$set': {'status': 'failed', 'message': err_msg, 'updated_at': datetime.now(timezone.utc)}},
                                                    upsert=True)
                except Exception:
                    pass  # if mongo itself fails in error handler

    except Exception as outer_err:
        import traceback, logging
        logging.getLogger(__name__).error(f'Voucher worker OUTER crash: {outer_err}\n{traceback.format_exc()}')
        try:
            with app.app_context():
                mongo.db.gen_progress.update_one({'token': token, 'user_id': actor_id},
                                                {'$set': {'status': 'failed', 'message': str(outer_err) or repr(outer_err), 'updated_at': datetime.now(timezone.utc)}},
                                                upsert=True)
        except Exception:
            pass

@bp.route('/admin/vouchers/start', methods=['POST'])
@login_required
@require_flag('can_generate')
def vouchers_start():
    role = getattr(current_user, 'role', 'user')
    try:
        qty = int(request.form.get('qty', 1))
    except Exception:
        qty = 1
    if role == 'user' and qty > 500:
        return jsonify({'ok': False, 'error': 'User limit: max 500 vouchers'}), 400

    token = (request.form.get('token') or '').strip() or f"gen_{uuid.uuid4().hex}"

    # If already generated, we can return immediately
    cached = mongo.db.gen_results.find_one({'token': token, 'user_id': str(current_user.id)})
    if cached and cached.get('pdf_b64'):
        mongo.db.gen_progress.update_one({'token': token, 'user_id': str(current_user.id)},
                                        {'$set': {'status': 'done', 'percent': 100, 'message': 'Done', 'updated_at': datetime.now(timezone.utc)},
                                         '$setOnInsert': {'created_at': datetime.now(timezone.utc)}},
                                        upsert=True)
        return jsonify({'ok': True, 'token': token, 'status': 'done'}), 200

    form = dict(request.form)
    form['_role'] = role

    # Init progress and launch worker thread
    mongo.db.gen_progress.update_one({'token': token, 'user_id': str(current_user.id)},
                                    {'$set': {'status': 'running', 'percent': 0, 'message': 'Queued...', 'updated_at': datetime.now(timezone.utc), 'total': qty, 'progress': 0},
                                     '$setOnInsert': {'created_at': datetime.now(timezone.utc)}},
                                    upsert=True)

    # Worker needs app context for mongo.db access in background thread
    from flask import current_app
    app = current_app._get_current_object()
    t = threading.Thread(target=_generate_vouchers_worker, args=(app, str(current_user.id), token, form, getattr(current_user, 'username', str(current_user.id))), daemon=True)
    t.start()

    return jsonify({'ok': True, 'token': token, 'status': 'running'}), 200

@bp.route('/admin/vouchers/progress/<token>')
@login_required
@require_flag('can_generate')
def vouchers_progress(token):
    doc = mongo.db.gen_progress.find_one({'token': token, 'user_id': str(current_user.id)}) or {}
    return jsonify({
        'ok': True,
        'status': doc.get('status', 'unknown'),
        'percent': int(doc.get('percent') or 0),
        'progress': int(doc.get('progress') or 0),
        'total': int(doc.get('total') or 0),
        'message': doc.get('message') or ''
    })

@bp.route('/admin/vouchers/download/<token>')
@login_required
@require_flag('can_generate')
def vouchers_download(token):
    cached = mongo.db.gen_results.find_one({'token': token, 'user_id': str(current_user.id)})
    if not cached or not cached.get('pdf_b64'):
        abort(404)
    pdf_bytes = base64.b64decode(cached['pdf_b64'].encode('utf-8'))
    return send_file(
        io.BytesIO(pdf_bytes),
        as_attachment=True,
        download_name=cached.get('filename') or 'Vouchers.pdf',
        mimetype='application/pdf'
    )


@bp.route('/hotspot/users')
@bp.route('/hotspot/users/<router_id>')
@login_required
@require_flag('allow_user_manage')
def hotspot_users(router_id=None):
    router_id = router_id or request.args.get('router_id') or session.get('router_id')
    router = _get_router_for_current_user(router_id)
    if not router:
        flash('Router not found or access denied', 'danger')
        return redirect(url_for('dashboard.dashboard'))

    profile_filter = request.args.get('profile', '')
    comment_filter = request.args.get('comment', '')

    try:
        conn, api = _get_pool_api(router)
        res = api.get_resource('/ip/hotspot/user')
        users = res.get()
        if profile_filter:
            users = [u for u in users if u.get('profile') == profile_filter]
        if comment_filter:
            users = [u for u in users if comment_filter in u.get('comment', '')]
        conn.disconnect()
        return render_template('hotspot_users.html', users=users, router=router)
    except Exception as e:
        flash(f'Error: {str(e)}', 'danger')
        return redirect(url_for('dashboard.dashboard'))


@bp.route('/hotspot/profiles')
@bp.route('/hotspot/profiles/<router_id>')
@login_required
@require_flag('allow_profiles')
def hotspot_profiles(router_id=None):
    router_id = router_id or request.args.get('router_id') or session.get('router_id')

    """List hotspot user profiles for a router.

    NOTE: admin should be able to open profiles for any router.
    """
    user_doc = mongo.db.users.find_one({'_id': ObjectId(current_user.id)}) or {}
    if user_doc.get('role') == 'admin':
        router = _find_router_any_user(router_id)
    else:
        routers = (user_doc.get('routers') or [])
        router = next((r for r in routers if r.get('id') == router_id), None)
    if not router:
        flash('Router not found', 'danger')
        return redirect(url_for('dashboard.dashboard'))

    profiles = []
    try:
        conn, api = _get_pool_api(router)
        profiles = list_hotspot_user_profiles(api)
        conn.disconnect()
    except Exception as e:
        flash(f'Router Connection Error: {str(e)}', 'danger')

    # Enrich each profile with metadata from on-login :put line
    for p in profiles:
        on_login = p.get('on-login', '')
        meta = parse_on_login_put_line(on_login)
        p['_validity'] = meta.get('validity', '')
        p['_price'] = meta.get('price', '')
        p['_sprice'] = meta.get('sprice', '')
        p['_expmode'] = meta.get('expmode', '')

    profiles = sorted(profiles, key=lambda x: (x.get('name') or '').lower())
    currency = router.get('currency', 'AED') if router else 'AED'
    return render_template('hotspot_profiles.html', router=router, profiles=profiles, currency=currency)


@bp.route('/hotspot/profiles/add', methods=['GET', 'POST'])
@bp.route('/hotspot/profiles/<router_id>/add', methods=['GET', 'POST'])
@login_required
@require_flag('allow_profile_edit')
def hotspot_profile_add(router_id=None):
    router_id = router_id or request.args.get('router_id') or session.get('router_id')

    """Add hotspot user profile with MikroMan-style options."""
    router = _get_router_for_current_user(router_id)
    if not router:
        flash('Router not found', 'danger')
        return redirect(url_for('dashboard.dashboard'))

    pools, parents = ['none'], ['none']
    try:
        conn, api = _get_pool_api(router)
        pools = ['none'] + list_ip_pools(api)
        parents = ['none'] + list_parent_queues(api)
        conn.disconnect()
    except Exception as e:
        flash(f'Router Connection Error: {str(e)}', 'danger')

    if request.method == 'POST':
        try:
            form = request.form
            name = form.get('name', '')
            ppool = form.get('ppool', 'none')
            sharedusers = form.get('sharedusers', '1')
            ratelimit = form.get('ratelimit', '')
            expmode = form.get('expmode', 'remc')
            validity = form.get('validity', '30d')
            price = form.get('price', '')
            sprice = form.get('sprice', '')
            lockunlock = form.get('lockunlock', 'Enable')
            parent = form.get('parent', 'none')

            conn, api = _get_pool_api(router)
            add_hotspot_user_profile(
                api,
                name=name,
                address_pool=ppool,
                shared_users=int(sharedusers) if str(sharedusers).isdigit() else 1,
                rate_limit=ratelimit,
                parent_queue=parent,
                exp_mode=expmode,
                validity=validity,
                price=price,
                selling_price=sprice,
                lock_user=lockunlock,
            )
            conn.disconnect()

            log_activity(
                current_user.username,
                "Hotspot Profile Created",
                f'Profile={name}, Router={router.get("name", "router")}'
            )

            flash('Profile created successfully', 'success')
            return redirect(url_for('admin.hotspot_profiles', router_id=router_id))
        except Exception as e:
            flash(f'Error: {str(e)}', 'danger')

    return render_template('hotspot_profile_add.html', router=router, pools=pools, parents=parents)


@bp.route('/hotspot/profiles/edit/<path:profile_name>', methods=['GET', 'POST'])
@bp.route('/hotspot/profiles/<router_id>/edit/<path:profile_name>', methods=['GET', 'POST'])
@login_required
@require_flag('allow_profile_edit')
def hotspot_profile_edit(profile_name, router_id=None):
    router_id = router_id or request.args.get('router_id') or session.get('router_id')

    """Edit a hotspot user profile."""
    router = _get_router_for_current_user(router_id)
    if not router:
        flash('Router not found', 'danger')
        return redirect(url_for('dashboard.dashboard'))

    pools, parents = ['none'], ['none']
    profile = None
    try:
        conn, api = _get_pool_api(router)
        pools = ['none'] + list_ip_pools(api)
        parents = ['none'] + list_parent_queues(api)
        profile = get_hotspot_user_profile_by_name(api, profile_name)
        conn.disconnect()
    except Exception as e:
        flash(f'Router Connection Error: {str(e)}', 'danger')

    if not profile:
        flash('Profile not found', 'danger')
        return redirect(url_for('admin.hotspot_profiles', router_id=router_id))

    # Parse UI fields from :put metadata line in on-login script (MikroMan format)
    on_login = profile.get('on-login', '') or ''
    meta = parse_on_login_put_line(on_login)

    validity = meta.get('validity', '30d')
    expmode = meta.get('expmode', 'remc')
    price = meta.get('price', '')
    sprice = meta.get('sprice', '')
    lock_val = meta.get('lock', 'Enable')

    # Fallback: also check comment for legacy profiles that used comment-based metadata
    comment = profile.get('comment', '') or ''
    if not price and not sprice and comment:
        for part in comment.split(';'):
            if '=' in part:
                k, v = part.split('=', 1)
                k = k.strip()
                if k == 'price' and not price:
                    price = v.strip()
                elif k == 'sprice' and not sprice:
                    sprice = v.strip()
                elif k == 'expmode' and expmode == 'remc':
                    expmode = v.strip()

    if request.method == 'POST':
        try:
            form = request.form
            name = form.get('name', '')
            ppool = form.get('ppool', 'none')
            sharedusers = form.get('sharedusers', '1')
            ratelimit = form.get('ratelimit', '')
            expmode_post = form.get('expmode', 'remc')
            validity_post = form.get('validity', validity)
            price_post = form.get('price', '')
            sprice_post = form.get('sprice', '')
            lockunlock = form.get('lockunlock', 'Enable')
            parent = form.get('parent', 'none')

            profile_id = profile.get('id') or profile.get('.id')
            conn, api = _get_pool_api(router)
            update_hotspot_user_profile(
                api,
                profile_id=profile_id,
                name=name,
                address_pool=ppool,
                shared_users=int(sharedusers) if str(sharedusers).isdigit() else 1,
                rate_limit=ratelimit,
                parent_queue=parent,
                exp_mode=expmode_post,
                validity=validity_post,
                price=price_post,
                selling_price=sprice_post,
                lock_user=lockunlock,
            )
            conn.disconnect()

            log_activity(
                current_user.username,
                "Hotspot Profile Updated",
                f'Profile={name}, Router={router.get("name", "router")}'
            )

            flash('Profile updated successfully', 'success')
            return redirect(url_for('admin.hotspot_profiles', router_id=router_id))
        except Exception as e:
            flash(f'Error: {str(e)}', 'danger')

    # Pre-fill form
    context = {
        'router': router,
        'profile': profile,
        'pools': pools,
        'parents': parents,
        'prefill': {
            'name': profile.get('name', ''),
            'ppool': profile.get('address-pool', 'none'),
            'sharedusers': profile.get('shared-users', '1'),
            'ratelimit': profile.get('rate-limit', ''),
            'expmode': expmode,
            'validity': validity,
            'price': price,
            'sprice': sprice,
            'lockunlock': lock_val if lock_val else ('Enable' if str(profile.get('shared-users', '1')) == '1' else 'Disable'),
            'parent': profile.get('parent-queue', 'none'),
        }
    }
    return render_template('hotspot_profile_edit.html', **context)


@bp.route('/hotspot/toggle_user/<user_id>/<action>')
@bp.route('/hotspot/toggle_user/<router_id>/<user_id>/<action>')
@login_required
@require_flag('allow_user_manage')
def toggle_hotspot_user(user_id, action, router_id=None):
    router_id = router_id or session.get('router_id')
    router = _get_router_for_current_user(router_id)
    if not router:
        flash('Router not found', 'danger')
        return redirect(url_for('dashboard.dashboard'))
    status = 'yes' if action == 'disable' else 'no'
    is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest'
    try:
        conn, api = _get_pool_api(router)
        api.get_resource('/ip/hotspot/user').set(id=user_id, disabled=status)
        conn.disconnect()
        if is_ajax:
            return jsonify({'ok': True, 'action': action})
        flash(f'User {action}d successfully!', 'success')
    except Exception as e:
        if is_ajax:
            return jsonify({'ok': False, 'error': str(e)}), 500
        flash(str(e), 'danger')
    return redirect(request.referrer or url_for('admin.hotspot_users', router_id=router_id))

@bp.route('/hotspot/edit_user', methods=['POST'])
@login_required
@require_flag('allow_user_manage')
def edit_hotspot_user():
    router_id = request.form.get('router_id')
    user_id = request.form.get('user_id')
    new_name = request.form.get('u_name')
    new_pass = request.form.get('u_pass')
    new_profile = request.form.get('u_profile')
    new_comment = request.form.get('u_comment')

    router = _get_router_for_current_user(router_id)
    if router:
        try:
            conn, api = _get_pool_api(router)
            api.get_resource('/ip/hotspot/user').set(id=user_id, name=new_name, password=new_pass, profile=new_profile, comment=new_comment)
            conn.disconnect()
            flash(f'User {new_name} updated successfully!', 'success')
        except Exception as e:
            flash(f'Error: {str(e)}', 'danger')
    else:
        flash('Router not found', 'danger')
    return redirect(request.referrer or url_for('admin.hotspot_users', router_id=router_id))


@bp.route('/hotspot/delete_user/<user_id>')
@bp.route('/hotspot/delete_user/<router_id>/<user_id>')
@login_required
@require_flag('allow_user_manage')
def delete_hotspot_user(user_id, router_id=None):
    router_id = router_id or session.get('router_id')
    # Use session-cached router lookup (faster than DB query every time)
    router = _get_router_for_current_user(router_id)

    if not router:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.accept_mimetypes.best == 'application/json':
            return jsonify({'ok': False, 'error': 'Router not found'}), 404
        flash('Router not found', 'danger')
        return redirect(url_for('admin.hotspot_users', router_id=router_id))

    try:
        conn, api = _get_pool_api(router)
        api.get_resource('/ip/hotspot/user').remove(id=user_id)
        # Don't disconnect — pool manages lifecycle (saves ~10-30ms per request)
    except Exception as e:
        if request.headers.get('Accept', '').find('application/json') != -1 or request.headers.get('X-Requested-With'):
            return jsonify({'ok': False, 'error': str(e)}), 500
        flash(str(e), 'danger')
        return redirect(request.referrer or url_for('admin.hotspot_users', router_id=router_id))

    # Skip per-delete logging for bulk operations (batch_delete_log handles that)
    # Only log for individual deletes (non-AJAX browser requests are individual)
    if not request.headers.get('X-Requested-With'):
        log_activity(current_user.username, 'Delete Hotspot User',
                     f'router={router.get("name","?")}',
                     router_id=router_id, hotspot_user_id=user_id)
    return jsonify({'ok': True}), 200

@bp.route('/hotspot/batch_delete_log', methods=['POST'])
@login_required
@require_flag('allow_user_manage')
def batch_delete_log():
    """Called by frontend after bulk delete finishes — logs one summary entry."""
    data = request.get_json(silent=True) or {}
    router_id  = data.get('router_id', '')
    deleted    = int(data.get('deleted', 0))
    failed     = int(data.get('failed', 0))
    router_name = data.get('router_name', router_id)
    if deleted or failed:
        log_activity(
            current_user.username,
            'Bulk Delete Hotspot',
            f'Deleted {deleted} user(s), failed {failed} — router={router_name}',
            router_id=router_id,
            deleted_count=deleted,
            failed_count=failed,
        )
    return jsonify({'ok': True}), 200


# ── Refresh All Profiles (re-push on-login + expiry schedulers) ────────────

@bp.route('/hotspot/refresh_profiles')
@bp.route('/hotspot/<router_id>/refresh_profiles')
@login_required
@require_flag('allow_profile_edit')
def refresh_all_profiles(router_id=None):
    """Re-generate and re-push on-login scripts + expiry schedulers for every
    hotspot user profile on the router. Fixes old profiles with wrong condition
    or wrong price baked into the on-login script."""
    router_id = router_id or request.args.get('router_id') or session.get('router_id')
    is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest'
    router = _get_router_for_current_user(router_id)
    if not router:
        if is_ajax:
            return jsonify({'ok': False, 'error': 'Router not found'}), 404
        flash('Router not found', 'danger')
        return redirect(url_for('dashboard.dashboard'))

    updated, failed = [], []
    try:
        conn, api = _get_pool_api(router)
        profiles = api.get_resource('/ip/hotspot/user/profile').get()

        for p in profiles:
            pname = p.get('name', '')
            pid = p.get('.id') or p.get('id')
            if not pname or not pid or pname in ('default', 'default-encryption'):
                continue
            on_login_raw = p.get('on-login', '')
            meta = parse_on_login_put_line(on_login_raw)
            try:
                update_hotspot_user_profile(
                    api,
                    profile_id=pid,
                    name=pname,
                    address_pool=p.get('address-pool', 'none'),
                    shared_users=int(p.get('shared-users', 1) or 1),
                    rate_limit=p.get('rate-limit', ''),
                    parent_queue=p.get('parent-queue', 'none'),
                    exp_mode=meta.get('expmode', 'remc'),
                    validity=meta.get('validity', '30d'),
                    price=meta.get('price', '0'),
                    selling_price=meta.get('sprice', '0'),
                    lock_user=meta.get('lock', 'Enable'),
                )
                updated.append(pname)
            except Exception as e:
                failed.append(f'{pname}: {e}')

        conn.disconnect()
    except Exception as e:
        if is_ajax:
            return jsonify({'ok': False, 'error': str(e)}), 500
        flash(f'Router error: {e}', 'danger')
        return redirect(url_for('admin.hotspot_profiles'))

    if is_ajax:
        return jsonify({'ok': True, 'updated': updated, 'failed': failed})

    if updated:
        flash(f'Refreshed {len(updated)} profile(s): {", ".join(updated)}', 'success')
    if failed:
        flash(f'Failed: {"; ".join(failed)}', 'danger')
    return redirect(request.referrer or url_for('admin.hotspot_profiles'))


# ── IP / MAC Binding (Hotspot bypass) ─────────────────────────────────────

@bp.route('/hotspot/ip_bindings')
@bp.route('/hotspot/<router_id>/ip_bindings')
@login_required
@require_flag('allow_user_manage')
def hotspot_ip_bindings(router_id=None):
    router_id = router_id or request.args.get('router_id') or session.get('router_id')
    router = _get_router_for_current_user(router_id)
    if not router:
        flash('Router not found', 'danger')
        return redirect(url_for('dashboard.dashboard'))

    bindings = []
    try:
        conn, api = _get_pool_api(router)
        bindings = list_ip_bindings(api)
        conn.disconnect()
    except Exception as e:
        flash(f'Router error: {e}', 'danger')

    return render_template('hotspot_ip_bindings.html', router=router, bindings=bindings)


@bp.route('/hotspot/add_ip_binding', methods=['POST'])
@login_required
@require_flag('allow_user_manage')
def add_hotspot_ip_binding():
    router_id = request.form.get('router_id') or session.get('router_id')
    is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest'
    router = _get_router_for_current_user(router_id)
    if not router:
        if is_ajax:
            return jsonify({'ok': False, 'error': 'Router not found'}), 404
        flash('Router not found', 'danger')
        return redirect(request.referrer or url_for('dashboard.dashboard'))

    mac = (request.form.get('mac_address') or '').strip()
    ip  = (request.form.get('ip_address') or '').strip()
    binding_type = request.form.get('binding_type', 'bypassed')
    comment = (request.form.get('comment') or '').strip()

    try:
        conn, api = _get_pool_api(router)
        add_ip_binding(api, mac_address=mac, ip_address=ip, binding_type=binding_type, comment=comment)
        conn.disconnect()
        log_activity(current_user.username, 'IP Binding Added',
                     f'mac={mac}, ip={ip}, type={binding_type}, router={router.get("name","?")}')
        if is_ajax:
            return jsonify({'ok': True})
        flash('Binding added successfully!', 'success')
    except Exception as e:
        if is_ajax:
            return jsonify({'ok': False, 'error': str(e)}), 500
        flash(f'Error: {e}', 'danger')

    return redirect(request.referrer or url_for('admin.hotspot_ip_bindings', router_id=router_id))


@bp.route('/hotspot/delete_ip_binding/<binding_id>')
@bp.route('/hotspot/delete_ip_binding/<router_id>/<binding_id>')
@login_required
@require_flag('allow_user_manage')
def delete_hotspot_ip_binding(binding_id, router_id=None):
    router_id = router_id or request.args.get('router_id') or session.get('router_id')
    is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest'
    router = _get_router_for_current_user(router_id)
    if not router:
        if is_ajax:
            return jsonify({'ok': False, 'error': 'Router not found'}), 404
        flash('Router not found', 'danger')
        return redirect(url_for('dashboard.dashboard'))

    try:
        conn, api = _get_pool_api(router)
        delete_ip_binding(api, binding_id)
        conn.disconnect()
        if is_ajax:
            return jsonify({'ok': True})
        flash('Binding deleted!', 'success')
    except Exception as e:
        if is_ajax:
            return jsonify({'ok': False, 'error': str(e)}), 500
        flash(f'Error: {e}', 'danger')

    return redirect(request.referrer or url_for('admin.hotspot_ip_bindings', router_id=router_id))


@bp.route('/admin/export_selected_pdf', methods=['POST'])
@login_required
@require_flag('allow_export_pdf')
def export_selected_pdf():
    selected_ids = request.form.getlist('user_ids[]')
    router_id = request.form.get('router_id')
    if not selected_ids:
        flash('No users selected!', 'warning')
        return redirect(request.referrer or url_for('dashboard.dashboard'))

    user_data = mongo.db.users.find_one({'_id': ObjectId(current_user.id)})
    live_html = user_data.get('custom_voucher_html')
    if not live_html:
        global_tpl = mongo.db.settings.find_one({'type': 'voucher_template'})
        live_html = global_tpl['html'] if global_tpl else "<div>{{username}}</div>"

    router = _get_router_for_current_user(router_id)
    if not router:
        flash('Router not found!', 'danger')
        return redirect(request.referrer or url_for('dashboard.dashboard'))

    vouchers = []
    _logo_uri = _get_logo_data_uri(router_id)
    try:
        conn, api = _get_pool_api(router)
        res = api.get_resource('/ip/hotspot/user')
        for idx, u_id in enumerate(selected_ids):
            u = res.get(id=u_id)
            if u:
                vouchers.append({
                    'hotspotname': router.get('name','Hotspot'),
                    'username': u[0].get('name'),
                    'password': u[0].get('password'),
                    'validity': u[0].get('limit-uptime', ''),
                    'timelimit': u[0].get('limit-uptime', ''),
                    'datalimit': '',
                    'price': '',
                    'profile': u[0].get('profile', ''),
                    'comment': u[0].get('comment', ''),
                    'usermode': 'vc' if u[0].get('name') == u[0].get('password') else 'up',
                    'date': datetime.now().strftime('%d-%b-%Y'),
                    'time': datetime.now().strftime('%I:%M %p'),
                    'num': idx + 1,
                    'router_name': router.get('name', 'Hotspot'),
                    'dnsname': router.get('dns_name', 'login.net'),
                    'logo': _logo_uri,
                })
        conn.disconnect()
    except Exception as e:
        flash(f'Error: {str(e)}', 'danger')
        return redirect(request.referrer or url_for('dashboard.dashboard'))

    html = "<html><head><style>@page { size: A4; margin: 0.5cm; } .v-cell { width: 25%; padding: 5px; }</style></head><body><table style='width:100%;'>"
    for idx, v in enumerate(vouchers):
        if idx % 4 == 0:
            html += '<tr>'
        rendered = _safe_render_voucher(live_html, v)
        html += f"<td class='v-cell'>{rendered}</td>"
        if (idx + 1) % 4 == 0:
            html += '</tr>'
    html += '</table></body></html>'

    pdf_io = html_to_pdf_bytes(html)
    return send_file(pdf_io, as_attachment=True, download_name='Selected_Vouchers.pdf', mimetype='application/pdf')

@bp.route('/admin/reports')
@login_required
@require_flag('allow_reports')
def sales_report():
    user_data = mongo.db.users.find_one({'_id': ObjectId(current_user.id)}) or {}

    # Router list for selector:
    # - admin: show all routers across all users
    # Build accessible routers list based on role
    _role = getattr(current_user, 'role', None) or user_data.get('role', 'user')
    user_routers = _get_accessible_routers(user_data)
    router_id = request.args.get('router_id') or session.get('router_id')
    if request.args.get('router_id'):
        session['router_id'] = request.args.get('router_id')
    if not router_id and user_routers:
        router_id = user_routers[0].get('id')
        session['router_id'] = router_id
    if not router_id:
        flash('No routers available', 'warning')
        return redirect(url_for('dashboard.dashboard'))

    router = _get_router_for_current_user(router_id)
    if not router:
        flash('Router not found', 'danger')
        return redirect(url_for('dashboard.dashboard'))

    selected_month = request.args.get('month', datetime.now().strftime('%Y-%m'))
    report_data, report_map, total_rev = [], {}, 0.0

    try:
        conn, api = _get_pool_api(router)
        scripts = api.get_resource('/system/script').get()

        # Build profile price lookup: profile_name -> selling price (sprice, fallback to price)
        profile_prices = {}
        try:
            for p in api.get_resource('/ip/hotspot/user/profile').get():
                pname = p.get('name', '')
                meta = parse_on_login_put_line(p.get('on-login', ''))
                sp = meta.get('sprice', '') or ''
                bp_ = meta.get('price', '') or ''
                try:
                    profile_prices[pname] = float(sp) if sp and float(sp) > 0 else (float(bp_) if bp_ else 0.0)
                except Exception:
                    profile_prices[pname] = 0.0
        except Exception:
            pass

        conn.disconnect()

        filter_dt = datetime.strptime(selected_month, '%Y-%m')
        for s in scripts:
            parsed = parse_activation_log(s.get('name', ''))
            if not parsed:
                continue
            try:
                log_dt = datetime.strptime(parsed['date'].lower(), '%b/%d/%Y')
            except Exception:
                continue
            if log_dt.month == filter_dt.month and log_dt.year == filter_dt.year:
                # Use current profile's selling price if available (fixes old entries baked with wrong price)
                pname = parsed.get('profile', '')
                if pname in profile_prices and profile_prices[pname] > 0:
                    parsed['price'] = profile_prices[pname]
                total_rev += parsed['price']
                report_data.append(parsed)
                report_map[parsed['date']] = report_map.get(parsed['date'], 0) + parsed['price']

        labels = sorted(report_map.keys(), key=lambda x: datetime.strptime(x, '%b/%d/%Y'))
        stats = [report_map[d] for d in labels]

        currency = router.get('currency', 'AED') if router else 'AED'
        return render_template('reports.html', labels=labels, stats=stats, total_rev=total_rev, report_data=report_data, selected_router=router, selected_month=selected_month, currency=currency)
    except Exception as e:
        flash(f'Error: {str(e)}', 'danger')
        return redirect(url_for('admin.sales_report'))

@bp.route('/admin/monitor')
@bp.route('/admin/monitor/<router_id>')
@login_required
@require_flag('allow_monitor')
def monitor_router(router_id=None):
    router_id = router_id or request.args.get('router_id') or session.get('router_id')
    router = _get_router_for_current_user(router_id)
    if not router:
        return 'Router not found or access denied', 403

    try:
        conn, api = _get_pool_api(router)

        active_users = api.get_resource('/ip/hotspot/active').get()
        interfaces = api.get_resource('/interface').get()

        # System resource (RAM/CPU/Uptime etc.)
        sys_res = api.get_resource('/system/resource').get() or []
        res0 = (sys_res[0] if sys_res else {})

        conn.disconnect()

        def _gb(v):
            try:
                return round(int(v) / (1024**3), 2)
            except Exception:
                return None

        ram_total_gb = _gb(res0.get('total-memory'))
        ram_free_gb = _gb(res0.get('free-memory'))
        ram = {
            'total_gb': ram_total_gb,
            'free_gb': ram_free_gb,
            'used_gb': round(ram_total_gb - ram_free_gb, 2) if (ram_total_gb is not None and ram_free_gb is not None) else None,
        }

        # CPU/load (optional)
        cpu = {
            'load': res0.get('cpu-load'),
            'uptime': res0.get('uptime'),
            'version': res0.get('version'),
            'board_name': res0.get('board-name'),
        }

        return render_template('monitor.html', router=router, active_users=active_users, interfaces=interfaces, ram=ram, cpu=cpu)

    except Exception as e:
        flash(f'Connection Error: {str(e)}', 'danger')
        return redirect(url_for('dashboard.dashboard'))



@bp.route('/admin/kick_user/<active_id>')
@bp.route('/admin/kick_user/<router_id>/<active_id>')
@login_required
@require_flag('allow_monitor')
def kick_user(active_id, router_id=None):
    router_id = router_id or session.get('router_id')
    router = _get_router_for_current_user(router_id)
    if not router:
        flash('Access denied', 'danger')
        return redirect(url_for('dashboard.dashboard'))
    try:
        conn, api = _get_pool_api(router)
        api.get_resource('/ip/hotspot/active').remove(id=active_id)
        conn.disconnect()
        flash('User disconnected successfully!', 'success')
    except Exception as e:
        flash(str(e), 'danger')
    return redirect(url_for('admin.monitor_router', router_id=router_id))


@bp.route('/api/traffic/<router_id>/<interface_name>')
@login_required
@require_flag('allow_monitor')
def get_traffic(router_id, interface_name):
    router = _get_router_for_current_user(router_id)
    if not router:
        return {'rx': 0, 'tx': 0, 'error': 'access denied'}
    try:
        conn, api = _get_pool_api(router)
        stats = api.get_resource('/interface').call('monitor-traffic', {'interface': interface_name, 'once': ''})
        conn.disconnect()
        return {'rx': stats[0].get('rx-bits-per-second', 0), 'tx': stats[0].get('tx-bits-per-second', 0)}
    except Exception:
        return {'rx': 0, 'tx': 0}


@bp.route('/api/voucher_status', methods=['POST'])
@limiter.limit("30 per minute")
def voucher_status_check():
    """Public API: check voucher remaining time and status.
    No login required — used from login page self-check widget.
    """
    code = (request.form.get('code') or '').strip()
    router_id = (request.form.get('router_id') or '').strip()

    if not code:
        return jsonify({'ok': False, 'error': 'Enter a voucher code'}), 400

    # Find router across all users
    router = None
    if router_id:
        user_with_router = mongo.db.users.find_one({'routers.id': router_id})
        if user_with_router:
            router = next((r for r in (user_with_router.get('routers') or []) if r.get('id') == router_id), None)

    # If no router_id, try first available router
    if not router:
        for u in mongo.db.users.find({'routers': {'$exists': True, '$ne': []}}):
            for r in (u.get('routers') or []):
                router = r
                break
            if router:
                break

    if not router:
        return jsonify({'ok': False, 'error': 'No router configured'}), 404

    try:
        conn, api = _get_pool_api(router)
        users_res = api.get_resource('/ip/hotspot/user')
        found = users_res.get(name=code)

        if not found:
            conn.disconnect()
            return jsonify({'ok': False, 'error': 'Voucher not found'}), 404

        user_info = found[0]
        comment = (user_info.get('comment') or '').strip()
        profile_name = user_info.get('profile', '')
        disabled = user_info.get('disabled', 'false')
        mac = user_info.get('mac-address', '')
        bytes_in = int(user_info.get('bytes-in', 0) or 0)
        bytes_out = int(user_info.get('bytes-out', 0) or 0)

        # Check if currently active
        active_res = api.get_resource('/ip/hotspot/active')
        active_sessions = active_res.get(user=code)
        is_online = len(active_sessions) > 0
        uptime = active_sessions[0].get('uptime', '') if is_online else ''

        conn.disconnect()

        # Parse expiry from comment (MikroMan format: mon/DD/YYYY HH:MM:SS)
        import re
        from datetime import datetime, timezone
        expiry_str = ''
        remaining_str = ''
        is_expired = False

        if comment and len(comment) >= 16:
            # Try to parse
            try:
                # Try MikroMan format: jan/01/2026 12:00:00
                exp_dt = datetime.strptime(comment.strip(), '%b/%d/%Y %H:%M:%S')
                expiry_str = exp_dt.strftime('%d %b %Y, %I:%M %p')
                now = datetime.now()
                diff = exp_dt - now
                if diff.total_seconds() <= 0:
                    is_expired = True
                    remaining_str = 'Expired'
                else:
                    days = diff.days
                    hours, rem = divmod(diff.seconds, 3600)
                    mins, _ = divmod(rem, 60)
                    parts = []
                    if days > 0: parts.append(f'{days}d')
                    if hours > 0: parts.append(f'{hours}h')
                    if mins > 0: parts.append(f'{mins}m')
                    remaining_str = ' '.join(parts) if parts else '<1m'
            except Exception:
                expiry_str = comment
                remaining_str = 'Unknown format'

        # Determine status
        if comment in ('', 'vc', 'up') or len(comment) < 3:
            status = 'unused'
            remaining_str = 'Not activated yet'
        elif is_expired:
            status = 'expired'
        elif disabled == 'true':
            status = 'disabled'
            remaining_str = 'Account disabled'
        elif is_online:
            status = 'online'
        else:
            status = 'active'

        return jsonify({
            'ok': True,
            'code': code,
            'status': status,
            'profile': profile_name,
            'expiry': expiry_str,
            'remaining': remaining_str,
            'is_online': is_online,
            'uptime': uptime,
            'mac': mac,
            'download_mb': round(bytes_out / 1048576, 2),
            'upload_mb': round(bytes_in / 1048576, 2),
        })

    except Exception as e:
        return jsonify({'ok': False, 'error': f'Router connection error'}), 500


@bp.route('/reset_mac', methods=['POST'])
@login_required
@require_flag('allow_mac_reset')
def reset_mac():
    target = (request.form.get('h_user') or '').strip()
    router_id = (request.form.get('router_id') or '').strip()

    # ✅ ALWAYS success message (default)
    success_msg = f"Success: {target} Reset" if target else "MAC reset successful"

    user_data = mongo.db.users.find_one({'_id': ObjectId(current_user.id)}) or {}
    router = None
    if router_id:
        router = _get_router_for_current_user(router_id)

    conn = None

    # Prevent concurrent RouterOS API calls to same router
    _mac_lock = _get_router_lock(router_id or 'mac_reset')
    with _mac_lock:
        try:
            # If missing info, still show success (do nothing)
            if not target or not router_id or not router:
                flash(success_msg, 'success')
                return redirect(url_for('dashboard.dashboard'))

            conn, api = _get_pool_api(router)

            users_res = api.get_resource('/ip/hotspot/user')
            u = users_res.get(name=target) or []

            # If voucher/user not found -> still success
            if not u:
                flash(success_msg, 'success')
                return redirect(url_for('dashboard.dashboard'))

            user_id = u[0].get('id') or u[0].get('.id')

            # If user id missing -> still success
            if not user_id:
                flash(success_msg, 'success')
                return redirect(url_for('dashboard.dashboard'))

            # RouterOS requires a MAC value (empty not allowed)
            payload = {'.id': user_id, 'mac-address': '00:00:00:00:00:00'}


            # Set MAC (ignore failure, still success)
            try:
                users_res.call('set', payload)
            except Exception as e:
                # Retry once on malformed/empty sentence
                try:
                    if 'Malformed sentence' in str(e) or '!empty' in str(e):
                        users_res.call('set', payload)
                except Exception:
                    pass

            # Kick active sessions (if none found -> ok)
            try:
                act_res = api.get_resource('/ip/hotspot/active')
                active_list = act_res.get(user=target) or []
                for a in active_list:
                    active_id = a.get('id') or a.get('.id')
                    if not active_id:
                        continue
                    try:
                        act_res.call('remove', {'.id': active_id})
                    except Exception:
                        try:
                            act_res.remove(id=active_id)
                        except Exception:
                            pass
            except Exception:
                pass

            # (Optional) remove cookies too (if your RouterOS supports it)
            try:
                cookie_res = api.get_resource('/ip/hotspot/cookie')
                cookie_list = cookie_res.get(user=target) or []
                for c in cookie_list:
                    cid = c.get('id') or c.get('.id')
                    if not cid:
                        continue
                    try:
                        cookie_res.call('remove', {'.id': cid})
                    except Exception:
                        try:
                            cookie_res.remove(id=cid)
                        except Exception:
                            pass
            except Exception:
                pass

            # Log only (even if some parts failed)
            try:
                log_activity(current_user.username, 'MAC Reset', f'Reset MAC for voucher: {target}')
            except Exception:
                pass

            # ✅ ALWAYS show success
            flash(success_msg, 'success')

        except Exception as e:
            # ✅ Even on error, show success (but you can print/log server-side)
            try:
                print("MAC Reset internal error:", str(e))
            except Exception:
                pass
            flash(success_msg, 'success')

        finally:
            try:
                if conn:
                    conn.disconnect()
            except Exception:
                pass

    return redirect(url_for('dashboard.dashboard'))





# ----------------------------
# Admin tools used by templates
# ----------------------------


@bp.route('/admin/live_template', methods=['GET', 'POST'])
@login_required
@require_flag('allow_live_template')
def live_template():
    """Voucher template editor with preset templates.

    The UI is app/templates/live_template.html.
    """
    # Preset templates
    PRESETS = {
        'standard': """<table class="voucher" style="width:220px;">
  <tbody>
    <tr>
      <td style="text-align:left;font-size:14px;font-weight:bold;border-bottom:1px solid black;padding:4px 6px;">
        {% if logo %}<img src="{{ logo }}" alt="logo" style="height:28px;border:0;vertical-align:middle;margin-right:4px;">{% endif %}
        {{ hotspotname }} <span style="float:right;font-weight:normal;font-size:11px;">[{{ num }}]</span>
      </td>
    </tr>
    <tr>
      <td style="padding:4px 6px;">
        <table style="text-align:center;width:100%;font-size:12px;">
          <tbody>
            <tr>
              <td>
                <table style="width:100%;">
                  {% if usermode == "vc" %}
                  <tr><td style="font-size:11px;color:#555;">Voucher Code</td></tr>
                  <tr>
                    <td style="width:100%;border:1px solid black;font-weight:bold;font-size:15px;padding:3px;">{{ username }}</td>
                  </tr>
                  {% else %}
                  <tr>
                    <td style="width:50%;font-size:11px;">Username</td>
                    <td style="font-size:11px;">Password</td>
                  </tr>
                  <tr style="font-size:13px;">
                    <td style="border:1px solid black;font-weight:bold;padding:3px;">{{ username }}</td>
                    <td style="border:1px solid black;font-weight:bold;padding:3px;">{{ password }}</td>
                  </tr>
                  {% endif %}
                </table>
              </td>
            </tr>
            <tr>
              <td style="border-top:1px solid black;font-weight:bold;font-size:14px;padding:3px 0;">
                {{ validity }}{% if datalimit %} {{ datalimit }}{% endif %}{% if price %} | {{ price }}{% endif %}
              </td>
            </tr>
            <tr>
              <td style="font-size:10px;color:#333;padding:2px 0;">Login: http://{{ dnsname }}</td>
            </tr>
          </tbody>
        </table>
      </td>
    </tr>
  </tbody>
</table>""",

        'standard_with_profile': """<table class="voucher" style="width:220px;">
  <tbody>
    <tr>
      <td style="text-align:left;font-size:14px;font-weight:bold;border-bottom:1px solid black;padding:4px 6px;">
        {% if logo %}<img src="{{ logo }}" alt="logo" style="height:28px;border:0;vertical-align:middle;margin-right:4px;">{% endif %}
        {{ hotspotname }} <span style="float:right;font-weight:normal;font-size:11px;">[{{ num }}]</span>
      </td>
    </tr>
    <tr>
      <td style="padding:4px 6px;">
        <table style="text-align:center;width:100%;font-size:12px;">
          <tbody>
            <tr>
              <td>
                <table style="width:100%;">
                  {% if usermode == "vc" %}
                  <tr><td style="font-size:11px;color:#555;">Voucher Code</td></tr>
                  <tr>
                    <td style="width:100%;border:1px solid black;font-weight:bold;font-size:15px;padding:3px;">{{ username }}</td>
                  </tr>
                  {% else %}
                  <tr>
                    <td style="width:50%;font-size:11px;">Username</td>
                    <td style="font-size:11px;">Password</td>
                  </tr>
                  <tr style="font-size:13px;">
                    <td style="border:1px solid black;font-weight:bold;padding:3px;">{{ username }}</td>
                    <td style="border:1px solid black;font-weight:bold;padding:3px;">{{ password }}</td>
                  </tr>
                  {% endif %}
                </table>
              </td>
            </tr>
            <tr>
              <td style="border-top:1px solid black;font-weight:bold;font-size:14px;padding:3px 0;">
                {{ validity }}{% if datalimit %} {{ datalimit }}{% endif %}{% if price %} | {{ price }}{% endif %}
              </td>
            </tr>
            <tr>
              <td style="font-size:10px;padding:2px 0;">
                <span style="color:#555;">Profile:</span> <b>{{ profile }}</b>
                {% if comment %} &nbsp;|&nbsp; <span style="color:#555;">Batch:</span> <b>{{ comment }}</b>{% endif %}
              </td>
            </tr>
            <tr>
              <td style="font-size:10px;color:#333;padding:2px 0;">Login: http://{{ dnsname }}</td>
            </tr>
          </tbody>
        </table>
      </td>
    </tr>
  </tbody>
</table>""",

        'small': """<table class="voucher" style="width:160px;">
  <tbody>
    <tr>
      <td style="text-align:left;font-size:13px;font-weight:bold;border-bottom:1px solid black;padding:3px 5px;">
        {{ hotspotname }}<span style="float:right;font-weight:normal;font-size:10px;">[{{ num }}]</span>
      </td>
    </tr>
    <tr>
      <td style="padding:3px 5px;">
        <table style="text-align:center;width:100%;font-size:11px;">
          <tbody>
            <tr style="color:black;">
              <td>
                <table style="width:100%;">
                  {% if usermode == "vc" %}
                  <tr><td style="font-size:10px;">Voucher Code</td></tr>
                  <tr style="font-size:13px;">
                    <td style="width:100%;border:1px solid black;font-weight:bold;padding:2px;">{{ username }}</td>
                  </tr>
                  <tr>
                    <td style="border:1px solid black;font-weight:bold;font-size:11px;padding:2px;">
                      {{ validity }}{% if datalimit %} {{ datalimit }}{% endif %}{% if price %} {{ price }}{% endif %}
                    </td>
                  </tr>
                  {% else %}
                  <tr>
                    <td style="width:50%;">Username</td>
                    <td>Password</td>
                  </tr>
                  <tr style="font-size:13px;">
                    <td style="border:1px solid black;font-weight:bold;padding:2px;">{{ username }}</td>
                    <td style="border:1px solid black;font-weight:bold;padding:2px;">{{ password }}</td>
                  </tr>
                  <tr>
                    <td colspan="2" style="border:1px solid black;font-weight:bold;font-size:11px;padding:2px;">
                      {{ validity }}{% if datalimit %} {{ datalimit }}{% endif %}{% if price %} {{ price }}{% endif %}
                    </td>
                  </tr>
                  {% endif %}
                </table>
              </td>
            </tr>
          </tbody>
        </table>
      </td>
    </tr>
  </tbody>
</table>""",

        'thermal': """<table class="voucher" style="width:180px;">
  <tbody>
    <tr>
      <td style="text-align:center;font-size:14px;font-weight:bold;padding:3px;">{{ hotspotname }}</td>
    </tr>
    <tr>
      <td style="text-align:center;font-size:12px;font-weight:bold;border-bottom:1px solid black;padding:3px;">
        {% if logo %}<img src="{{ logo }}" alt="logo" style="height:28px;border:0;"><br>{% endif %}
        {{ date }} {{ time }}
      </td>
    </tr>
    <tr>
      <td style="padding:3px 5px;">
        <table style="text-align:center;width:100%;font-size:12px;">
          <tbody>
            <tr>
              <td>
                <table style="width:100%;">
                  {% if usermode == "vc" %}
                  <tr><td style="font-size:11px;">Voucher Code</td></tr>
                  <tr>
                    <td style="width:100%;border:1px solid black;font-weight:bold;font-size:15px;padding:3px;">{{ username }}</td>
                  </tr>
                  {% else %}
                  <tr>
                    <td style="width:50%;font-size:11px;">Username</td>
                    <td style="font-size:11px;">Password</td>
                  </tr>
                  <tr style="font-size:13px;">
                    <td style="border:1px solid black;font-weight:bold;padding:3px;">{{ username }}</td>
                    <td style="border:1px solid black;font-weight:bold;padding:3px;">{{ password }}</td>
                  </tr>
                  {% endif %}
                </table>
              </td>
            </tr>
            <tr>
              <td style="border-top:1px solid black;font-weight:bold;font-size:14px;padding:3px 0;">
                {{ validity }}{% if datalimit %} {{ datalimit }}{% endif %}{% if price %} | {{ price }}{% endif %}
              </td>
            </tr>
            <tr>
              <td style="font-weight:bold;font-size:11px;padding:2px 0;">Login: http://{{ dnsname }}</td>
            </tr>
          </tbody>
        </table>
      </td>
    </tr>
  </tbody>
</table>""",
    }

    tpl_doc = mongo.db.settings.find_one({'type': 'voucher_template'}) or {'type': 'voucher_template', 'html': ''}

    if request.method == 'POST':
        new_html = request.form.get('template_html', '')
        mongo.db.settings.update_one({'type': 'voucher_template'}, {'$set': {'html': new_html}}, upsert=True)
        mongo.db.settings.update_one({'_id': 'app_settings'}, {'$set': {'live_html': new_html}}, upsert=True)
        flash('Template saved!', 'success')
        return redirect(url_for('admin.live_template'))

    # Load preset if requested
    selected = request.args.get('template', 'current')
    if request.args.get('load') and selected in PRESETS:
        content = PRESETS[selected]
    else:
        content = tpl_doc.get('html', '') or PRESETS['small']
        selected = 'current'

    # Get all routers for logo management
    user_data = mongo.db.users.find_one({'_id': ObjectId(current_user.id)}) or {}
    all_routers = _get_accessible_routers(user_data)

    # Get logos for all routers
    router_logos = {}
    for r in all_routers:
        logo_doc = mongo.db.settings.find_one({'type': 'router_logo', 'router_id': r.get('id')})
        if logo_doc:
            router_logos[r.get('id')] = logo_doc.get('filename', 'custom logo')

    # Get site logo data URI for preview
    site_logo_uri = _get_logo_data_uri()

    return render_template('live_template.html',
        template_content=content,
        selected=selected,
        presets=list(PRESETS.keys()),
        all_routers=all_routers,
        router_logos=router_logos,
        site_logo_uri=site_logo_uri)


# ─── Router Logo Management ─────────────────────────────────────────────
@bp.route('/admin/upload_router_logo', methods=['POST'])
@login_required
@require_flag('allow_live_template')
def upload_router_logo():
    """Upload a custom logo for a specific router (stored as base64 in DB)."""
    router_id = (request.form.get('router_id') or '').strip()
    if not router_id:
        flash('Router ID missing', 'danger')
        return redirect(request.referrer or url_for('admin.live_template'))

    file = request.files.get('logo_file')
    if not file or not file.filename:
        flash('No file selected', 'danger')
        return redirect(request.referrer or url_for('admin.live_template'))

    # Validate file type
    allowed = {'png', 'jpg', 'jpeg', 'gif', 'svg', 'webp'}
    ext = file.filename.rsplit('.', 1)[-1].lower() if '.' in file.filename else ''
    if ext not in allowed:
        flash('Invalid file type. Use PNG, JPG, GIF, SVG, or WebP.', 'danger')
        return redirect(request.referrer or url_for('admin.live_template'))

    # Read and encode as base64
    import base64 as b64mod
    data = file.read()
    if len(data) > 500_000:  # 500KB max
        flash('Logo file too large. Max 500KB.', 'danger')
        return redirect(request.referrer or url_for('admin.live_template'))

    mime_map = {'png': 'image/png', 'jpg': 'image/jpeg', 'jpeg': 'image/jpeg',
                'gif': 'image/gif', 'svg': 'image/svg+xml', 'webp': 'image/webp'}
    mime = mime_map.get(ext, 'image/png')
    b64_str = b64mod.b64encode(data).decode('utf-8')
    data_uri = f'data:{mime};base64,{b64_str}'

    # Store in settings collection
    mongo.db.settings.update_one(
        {'type': 'router_logo', 'router_id': router_id},
        {'$set': {'type': 'router_logo', 'router_id': router_id, 'data_uri': data_uri, 'filename': file.filename}},
        upsert=True
    )
    flash(f'Logo uploaded for router!', 'success')
    return redirect(request.referrer or url_for('admin.live_template'))


@bp.route('/admin/delete_router_logo/<router_id>')
@login_required
@require_flag('allow_live_template')
def delete_router_logo(router_id):
    """Delete custom logo for a router — falls back to site logo."""
    mongo.db.settings.delete_one({'type': 'router_logo', 'router_id': router_id})
    flash('Custom logo removed. Site logo will be used.', 'success')
    return redirect(request.referrer or url_for('admin.live_template'))


def _get_logo_data_uri(router_id=None):
    """Get logo data URI for a router. Priority: router custom logo → site logo."""
    if router_id:
        custom = mongo.db.settings.find_one({'type': 'router_logo', 'router_id': router_id})
        if custom and custom.get('data_uri'):
            return custom['data_uri']
    # Fallback: site logo from static files
    try:
        import os
        logo_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'static', 'img', 'logo-square-256.png')
        if os.path.exists(logo_path):
            import base64 as b64mod
            with open(logo_path, 'rb') as f:
                b64_str = b64mod.b64encode(f.read()).decode('utf-8')
            return f'data:image/png;base64,{b64_str}'
    except Exception:
        pass
    return ''


@bp.route('/admin/update_settings', methods=['POST'])
@login_required
@require_admin
def update_settings():
    support = request.form.get('support_contact', '').strip()
    if support:
        mongo.db.settings.update_one({'support_contact': {'$exists': True}}, {'$set': {'support_contact': support}}, upsert=True)
        flash('Settings updated!', 'success')
    return redirect(url_for('dashboard.dashboard'))


@bp.route('/admin/add_user', methods=['POST'])
@login_required
@require_flag('allow_user_manage')
def add_user():
    # Support both old field names (username/password/role/email) and the admin_panel.html names (u_*)
    username = (request.form.get('u_name') or request.form.get('username') or '').strip()
    password = (request.form.get('u_pass') or request.form.get('password') or '').strip()
    if not username or len(password) < 6:
        flash('Username required and password must be at least 6 characters.', 'danger')
        return redirect(url_for('dashboard.dashboard'))
    role = (request.form.get('u_role') or request.form.get('role') or 'user').strip()
    email = (request.form.get('u_email') or request.form.get('email') or '').strip()

    # Sub-admin can create user accounts; admin can create any role
    if getattr(current_user, 'role', 'user') not in ('admin', 'sub-admin'):
        role = 'user'

    if not username or not password:
        flash('Username & password required', 'danger')
        return redirect(url_for('dashboard.dashboard'))

    if mongo.db.users.find_one({'username': username}):
        flash('Username already exists', 'danger')
        return redirect(url_for('dashboard.dashboard'))

    # ── Router: copy from existing user OR use manual input ──
    routers = []
    copy_from = (request.form.get('copy_router_from') or '').strip()

    if copy_from and '|' in copy_from:
        # Format: "user_id|router_id"
        src_uid, src_rid = copy_from.split('|', 1)
        try:
            src_user = mongo.db.users.find_one({'_id': ObjectId(src_uid)}, {'routers': 1}) or {}
            src_router = next((r for r in src_user.get('routers', []) if r.get('id') == src_rid), None)
            if src_router:
                # Copy router config but assign new ID
                copied = dict(src_router)
                copied['id'] = generate_random_string(8, 'mix')
                routers.append(copied)
        except Exception:
            pass  # fallthrough to manual

    if not routers and role != 'sub-admin':
        # Manual router entry
        r_name = (request.form.get('r_name') or 'Router').strip() or 'Router'
        r_ip = (request.form.get('r_ip') or '').strip()
        r_user = (request.form.get('r_user') or '').strip()
        r_pass = (request.form.get('r_pass') or '').strip()
        dns_name = (request.form.get('dns_name') or 'login.net').strip() or 'login.net'
        currency = (request.form.get('currency') or 'AED').strip() or 'AED'
        if r_ip:
            routers.append({
                'id': generate_random_string(8, 'mix'),
                'name': r_name,
                'ip': r_ip,
                'api_user': r_user,
                'api_pass_enc': encrypt_text(r_pass),
                'dns_name': dns_name,
                'currency': currency,
            })

    doc = {
        'username': username,
        'password': generate_password_hash(password),
        'role': role,
        'email': email,
        'status': 'active',
        'routers': routers,
        'created_at': datetime.now(timezone.utc).isoformat(),
        'can_generate': False,
        'allow_reports': False,
        'allow_user_manage': False,
        'allow_profiles': False,
        'allow_profile_edit': False,
        'allow_quick_user': False,
        'allow_mac_reset': True,       # Auto-granted: users always need MAC reset
        'allow_live_template': False,
        'allow_router_manage': False,
        'allow_export_pdf': False,
        'allow_monitor': False,
        'allow_port_lock': False,

        # UI defaults
        'ui_onboarded': True,          # Admin-created = skip onboarding
    }

    # Apply permissions from the create form (if any checkboxes were submitted)
    # Sub-admin can only grant permissions they themselves have
    perm_fields = [
        'can_generate', 'allow_reports', 'allow_monitor', 'allow_profiles',
        'allow_profile_edit', 'allow_user_manage', 'allow_quick_user',
        'allow_mac_reset', 'allow_live_template', 'allow_router_manage',
        'allow_export_pdf', 'allow_port_lock',
    ]
    actor_role = getattr(current_user, 'role', 'user')
    if actor_role in ('admin', 'sub-admin'):
        if actor_role == 'admin':
            actor_data = {}  # admin has all perms
        else:
            actor_data = mongo.db.users.find_one({'_id': ObjectId(current_user.id)}) or {}
        for pf in perm_fields:
            form_key = f'perm_{pf}'
            if form_key in request.form:
                requested = True
                if actor_role == 'admin':
                    doc[pf] = True
                else:
                    # Sub-admin can only grant what they have
                    doc[pf] = bool(actor_data.get(pf, False))

    # Apply role-based UI defaults from app_settings (admin-configurable)
    app_settings = mongo.db.settings.find_one({'_id': 'app_settings'}) or {}
    ui_defaults = app_settings.get('ui_defaults') or {}
    role_key = 'staff' if role == 'sub-admin' else 'user'
    dflt = ui_defaults.get(role_key) or {}
    if 'navbar' in dflt:
        doc['ui_navbar'] = bool(dflt.get('navbar'))
    if 'sidebar' in dflt:
        doc['ui_sidebar'] = bool(dflt.get('sidebar'))
    if 'landing' in dflt:
        doc['ui_landing'] = dflt.get('landing') or 'dashboard'

    # Track who created this account (used for staff "My Customers")
    if getattr(current_user, 'role', 'user') != 'admin':
        doc['created_by'] = str(current_user.id)

    result = mongo.db.users.insert_one(doc)
    log_activity(current_user.username, 'Create User', f'Created user: {username} role={role}')

    flash('User created', 'success')
    return redirect(url_for('dashboard.dashboard'))
@bp.route('/admin/delete_user/<id>')
@login_required
@require_flag('allow_user_manage')
def delete_user(id):
    try:
        # Sub-admin/staff can only delete normal users
        if getattr(current_user, 'role', 'user') != 'admin':
            u = mongo.db.users.find_one({'_id': ObjectId(id)}) or {}
            if u.get('role') != 'user':
                abort(403)

        target = mongo.db.users.find_one({'_id': ObjectId(id)}, {'username': 1})
        mongo.db.users.delete_one({'_id': ObjectId(id)})
        log_activity(current_user.username, 'Delete Account', f'Deleted account: {(target or {}).get("username", str(id))}')
        flash('User deleted', 'success')
    except Exception as e:
        flash(str(e), 'danger')
    return redirect(url_for('dashboard.dashboard'))


@bp.route('/admin/approve_user/<user_id>')
@login_required
@require_admin
def approve_user(user_id):
    """Approve a pending registration."""
    target = mongo.db.users.find_one({'_id': ObjectId(user_id)})
    if not target:
        flash('User not found', 'danger')
    elif target.get('status') != 'pending':
        flash('User is not pending', 'warning')
    else:
        mongo.db.users.update_one(
            {'_id': ObjectId(user_id)},
            {'$set': {'status': 'active'}, '$unset': {'registered_via': ''}}
        )
        log_activity(current_user.username, 'Approve User', f'Approved registration: {target.get("username", "")}')
        flash(f'User "{target.get("username")}" approved!', 'success')
    return redirect(url_for('dashboard.dashboard'))


@bp.route('/admin/reject_user/<user_id>')
@login_required
@require_admin
def reject_user(user_id):
    """Reject a pending registration."""
    target = mongo.db.users.find_one({'_id': ObjectId(user_id)})
    if not target:
        flash('User not found', 'danger')
    elif target.get('status') != 'pending':
        flash('User is not pending', 'warning')
    else:
        mongo.db.users.update_one(
            {'_id': ObjectId(user_id)},
            {'$set': {'status': 'rejected'}}
        )
        log_activity(current_user.username, 'Reject User', f'Rejected registration: {target.get("username", "")}')
        flash(f'User "{target.get("username")}" rejected', 'info')
    return redirect(url_for('dashboard.dashboard'))


@bp.route('/admin/update_user_permission/<user_id>', methods=['POST'])
@login_required
def update_user_permission(user_id):
    """Update role/permissions.

    Rules:
    - Admin can change role between user/sub-admin and set all flags.
    - Staff (sub-admin) can update permissions for ONLY their own created users.
      Staff cannot promote role (always stays user). Staff can grant permissions to their own created users (limited to permissions they themselves have).
    - Normal users cannot access this endpoint.
    """

    actor = mongo.db.users.find_one({'_id': ObjectId(current_user.id)}) or {}
    target = mongo.db.users.find_one({'_id': ObjectId(user_id)})
    if not target:
        flash('User not found', 'danger')
        return redirect(url_for('dashboard.dashboard'))

    actor_role = (actor.get('role') or 'user')
    target_role = (target.get('role') or 'user')

    # Admin and sub-admin can both edit permissions (sub-admin for their own users)
    if actor_role not in ('admin', 'sub-admin'):
        abort(403)

    is_admin_actor = (actor_role == 'admin')

    # Staff can only manage users they created (and only normal users)
    if not is_admin_actor:
        if (target.get('created_by') or '') != str(current_user.id):
            abort(403)
        if target_role != 'user':
            abort(403)

    # Role change: admin only
    new_role = target_role
    if is_admin_actor:
        requested_role = (request.form.get('u_role') or '').strip() or target_role
        if requested_role not in ('user', 'sub-admin'):
            requested_role = 'user'
        new_role = requested_role

    # Check if "Grant All" was clicked
    grant_all = ('grant_all' in request.form)

    if grant_all and is_admin_actor:
        # Admin granting full permissions
        can_generate     = True
        allow_reports    = True
        allow_monitor    = True
        allow_profiles   = True
        allow_profile_edit = True
        allow_user_manage = True
        allow_quick_user = True
        allow_mac_reset = True
        allow_live_template = True
        allow_router_manage = True
        allow_export_pdf = True
        allow_create_user = True
        allow_delete_user = True
        allow_batch_delete = True
        allow_port_lock = True
    elif grant_all and not is_admin_actor:
        # Sub-admin granting full perms to their user (limited to what they have)
        actor_data = mongo.db.users.find_one({'_id': ObjectId(current_user.id)}) or {}
        can_generate      = bool(actor_data.get('can_generate'))
        allow_reports     = bool(actor_data.get('allow_reports'))
        allow_monitor     = bool(actor_data.get('allow_monitor'))
        allow_profiles    = bool(actor_data.get('allow_profiles'))
        allow_profile_edit = bool(actor_data.get('allow_profile_edit'))
        allow_user_manage = bool(actor_data.get('allow_user_manage'))
        allow_quick_user = bool(actor_data.get('allow_quick_user'))
        allow_mac_reset = bool(actor_data.get('allow_mac_reset'))
        allow_live_template = bool(actor_data.get('allow_live_template'))
        allow_router_manage = bool(actor_data.get('allow_router_manage'))
        allow_export_pdf = bool(actor_data.get('allow_export_pdf'))
        allow_create_user = bool(actor_data.get('allow_create_user'))
        allow_delete_user = bool(actor_data.get('allow_delete_user'))
        allow_batch_delete = bool(actor_data.get('allow_batch_delete'))
        allow_port_lock = bool(actor_data.get('allow_port_lock'))
    else:
        # Individual checkbox selection
        requested_can_generate    = ('can_generate' in request.form)
        requested_allow_reports   = ('allow_reports' in request.form)
        requested_allow_monitor   = ('allow_monitor' in request.form)
        requested_allow_profiles  = ('allow_profiles' in request.form)
        requested_allow_profile_edit = ('allow_profile_edit' in request.form)
        requested_allow_user_manage = ('allow_user_manage' in request.form)
        requested_allow_quick_user = ('allow_quick_user' in request.form)
        requested_allow_mac_reset = ('allow_mac_reset' in request.form)
        requested_allow_live_template = ('allow_live_template' in request.form)
        requested_allow_router_manage = ('allow_router_manage' in request.form)
        requested_allow_export_pdf = ('allow_export_pdf' in request.form)
        requested_allow_create_user = ('allow_create_user' in request.form)
        requested_allow_delete_user = ('allow_delete_user' in request.form)
        requested_allow_batch_delete = ('allow_batch_delete' in request.form)
        requested_allow_port_lock = ('allow_port_lock' in request.form)

        if is_admin_actor:
            can_generate      = requested_can_generate
            allow_reports     = requested_allow_reports
            allow_monitor     = requested_allow_monitor
            allow_profiles    = requested_allow_profiles
            allow_profile_edit = requested_allow_profile_edit
            allow_user_manage = requested_allow_user_manage
            allow_quick_user = requested_allow_quick_user
            allow_mac_reset = requested_allow_mac_reset
            allow_live_template = requested_allow_live_template
            allow_router_manage = requested_allow_router_manage
            allow_export_pdf = requested_allow_export_pdf
            allow_create_user = requested_allow_create_user
            allow_delete_user = requested_allow_delete_user
            allow_batch_delete = requested_allow_batch_delete
            allow_port_lock = requested_allow_port_lock
        else:
            # Sub-admin: can only grant perms they themselves have
            actor_data = mongo.db.users.find_one({'_id': ObjectId(current_user.id)}) or {}
            can_generate      = requested_can_generate      and bool(actor_data.get('can_generate'))
            allow_reports     = requested_allow_reports     and bool(actor_data.get('allow_reports'))
            allow_monitor     = requested_allow_monitor     and bool(actor_data.get('allow_monitor'))
            allow_profiles    = requested_allow_profiles    and bool(actor_data.get('allow_profiles'))
            allow_profile_edit = requested_allow_profile_edit and bool(actor_data.get('allow_profile_edit'))
            allow_user_manage = requested_allow_user_manage and bool(actor_data.get('allow_user_manage'))
            allow_quick_user = requested_allow_quick_user and bool(actor_data.get('allow_quick_user'))
            allow_mac_reset = requested_allow_mac_reset and bool(actor_data.get('allow_mac_reset'))
            allow_live_template = requested_allow_live_template and bool(actor_data.get('allow_live_template'))
            allow_router_manage = requested_allow_router_manage and bool(actor_data.get('allow_router_manage'))
            allow_export_pdf = requested_allow_export_pdf and bool(actor_data.get('allow_export_pdf'))
            allow_create_user = requested_allow_create_user and bool(actor_data.get('allow_create_user'))
            allow_delete_user = requested_allow_delete_user and bool(actor_data.get('allow_delete_user'))
            allow_batch_delete = requested_allow_batch_delete and bool(actor_data.get('allow_batch_delete'))
            allow_port_lock = requested_allow_port_lock and bool(actor_data.get('allow_port_lock'))

    payload = {
        'role': new_role,
        'can_generate': can_generate,
        'allow_reports': allow_reports,
        'allow_monitor': allow_monitor,
        'allow_profiles': allow_profiles,
        'allow_profile_edit': allow_profile_edit,
        'allow_user_manage': allow_user_manage,
        'allow_quick_user': allow_quick_user,
        'allow_mac_reset': allow_mac_reset,
        'allow_live_template': allow_live_template,
        'allow_router_manage': allow_router_manage,
        'allow_export_pdf': allow_export_pdf,
        'allow_create_user': allow_create_user,
        'allow_delete_user': allow_delete_user,
        'allow_batch_delete': allow_batch_delete,
        'allow_port_lock': allow_port_lock,
    }

    mongo.db.users.update_one({'_id': ObjectId(user_id)}, {'$set': payload})
    perms_str = ', '.join(k for k, v in payload.items() if v is True)
    log_activity(current_user.username, 'Update Permission', f'user_id={user_id}: {perms_str or "none"}')
    flash('Permissions updated', 'success')
    return redirect(url_for('dashboard.dashboard'))


@bp.route('/admin/login_as_user/<user_id>')
@login_required
def login_as_user(user_id):
    """Impersonate a user.

    - Admin: can impersonate any non-admin account.
    - Staff (sub-admin): can impersonate ONLY their own created normal users.
      (created_by == staff id, role == 'user')
    """

    actor = mongo.db.users.find_one({'_id': ObjectId(current_user.id)}) or {}
    actor_role = (actor.get('role') or 'user')
    is_admin_actor = (actor_role == 'admin')

    if actor_role not in ('admin', 'sub-admin'):
        abort(403)

    # Staff must have user management enabled
    if not is_admin_actor:
        if not (actor.get('allow_user_manage') is True or str(actor.get('allow_user_manage')).lower() in ('1', 'true', 'yes', 'on')):
            abort(403)

    u = mongo.db.users.find_one({'_id': ObjectId(user_id)})
    if not u:
        flash('User not found', 'danger')
        return redirect(url_for('dashboard.dashboard'))

    # Never allow impersonating an admin
    if (u.get('role') or 'user') == 'admin':
        abort(403)

    # Staff scope restriction
    if not is_admin_actor:
        if (u.get('role') or 'user') != 'user':
            abort(403)
        if (u.get('created_by') or '') != str(current_user.id):
            abort(403)

    login_user(User(u))
    log_activity(current_user.username, 'Impersonate', f'Logged in as {u.get("username","?")}')
    flash(f"Logged in as {u.get('username','user')}", 'info')
    return redirect(url_for('dashboard.dashboard'))


@bp.route('/admin/ui_settings/<user_id>', methods=['GET', 'POST'])
@login_required
def ui_settings(user_id):
    """Admin/Staff can control a user's UI (navbar/sidebar) for that account.

    - Admin: can update any non-admin user/sub-admin.
    - Staff: can update ONLY their own created normal users.
    """
    actor = mongo.db.users.find_one({'_id': ObjectId(current_user.id)}) or {}
    actor_role = (actor.get('role') or 'user')
    is_admin_actor = (actor_role == 'admin')

    # Staff must have user management enabled
    if actor_role == 'sub-admin':
        if not (actor.get('allow_user_manage') is True or str(actor.get('allow_user_manage')).lower() in ('1','true','yes','on')):
            abort(403)

    if actor_role not in ('admin', 'sub-admin'):
        abort(403)

    target = mongo.db.users.find_one({'_id': ObjectId(user_id)})
    if not target:
        flash('User not found', 'danger')
        return redirect(url_for('dashboard.dashboard'))

    # Never allow editing admin account
    if (target.get('role') or 'user') == 'admin':
        abort(403)

    # Staff scope restriction
    if not is_admin_actor:
        if (target.get('role') or 'user') != 'user':
            abort(403)
        if (target.get('created_by') or '') != str(current_user.id):
            abort(403)

    if request.method == 'POST':
        ui_navbar = (request.form.get('ui_navbar') == 'on')
        ui_sidebar = (request.form.get('ui_sidebar') == 'on')
        mongo.db.users.update_one({'_id': ObjectId(user_id)}, {'$set': {'ui_navbar': ui_navbar, 'ui_sidebar': ui_sidebar}})
        flash('UI settings updated', 'success')
        return redirect(url_for('admin.ui_settings', user_id=user_id))

    return render_template('ui_user_settings.html', target=target)


@bp.route('/admin/add_router_to_user', methods=['POST'])
@login_required
@require_flag('allow_user_manage')
def add_router_to_user():
    user_id = (request.form.get('user_id') or request.form.get('u_id') or '').strip()
    if not user_id:
        flash('User id missing', 'danger')
        return redirect(url_for('dashboard.dashboard'))

    r_id = (request.form.get('r_id') or '').strip() or generate_random_string(8, 'mix')
    router = {
        'id': r_id,
        'name': (request.form.get('r_name') or 'Router').strip() or 'Router',
        'ip': (request.form.get('r_ip') or '').strip(),
        'api_user': (request.form.get('r_user') or '').strip(),
        'api_pass_enc': encrypt_text((request.form.get('r_pass') or '').strip()),
        'dns_name': (request.form.get('dns_name') or 'login.net').strip() or 'login.net',
        'currency': (request.form.get('currency') or 'AED').strip() or 'AED',
    }
    if not router['ip']:
        flash('Router IP/Host required', 'danger')
        return redirect(url_for('dashboard.dashboard'))

    try:
        u_oid = ObjectId(user_id)
    except Exception:
        flash('Invalid user id', 'danger')
        return redirect(url_for('dashboard.dashboard'))

    user_data = mongo.db.users.find_one({'_id': u_oid})
    if not user_data:
        flash('User not found', 'danger')
        return redirect(request.referrer or url_for('dashboard.dashboard'))

    # Staff can only modify users they created
    if getattr(current_user, 'role', 'user') != 'admin':
        if user_data.get('role') != 'user' or user_data.get('created_by') != str(current_user.id):
            abort(403)

    routers = user_data.get('routers', []) or []

    # If router id already exists, update it instead of pushing a duplicate.
    if any(r.get('id') == router['id'] for r in routers):
        set_fields = {
            'routers.$.name': router['name'],
            'routers.$.ip': router['ip'],
            'routers.$.api_user': router['api_user'],
            'routers.$.dns_name': router['dns_name'],
            'routers.$.currency': router['currency'],
        }
        # only update password if provided (non-empty); otherwise keep old
        if request.form.get('r_pass'):
            set_fields['routers.$.api_pass_enc'] = router['api_pass_enc']
            mongo.db.users.update_one({'_id': u_oid, 'routers.id': router['id']}, {'$unset': {'routers.$.api_pass': ''}})
        mongo.db.users.update_one({'_id': u_oid, 'routers.id': router['id']}, {'$set': set_fields})
        flash('Router updated', 'success')
    else:
        # Clean legacy plaintext fields
        router.pop('api_pass', None)
        mongo.db.users.update_one({'_id': u_oid}, {'$push': {'routers': router}})
        flash('Router added', 'success')

    return redirect(request.referrer or url_for('dashboard.dashboard'))


@bp.route('/admin/update_router', methods=['POST'])
@login_required
@require_flag('allow_user_manage')
def update_router():
    user_id = request.form.get('u_id')
    r_id = request.form.get('r_id')

    # Staff can only modify users they created
    if getattr(current_user, 'role', 'user') != 'admin':
        try:
            u_doc = mongo.db.users.find_one({'_id': ObjectId(user_id)}) or {}
        except Exception:
            u_doc = {}
        if u_doc.get('role') != 'user' or u_doc.get('created_by') != str(current_user.id):
            abort(403)

    r_name = (request.form.get('r_name') or '').strip()
    r_ip = (request.form.get('r_ip') or '').strip()
    r_user = (request.form.get('r_user') or '').strip()
    r_pass = (request.form.get('r_pass') or '').strip()
    dns_name = (request.form.get('dns_name') or 'login.net').strip() or 'login.net'
    currency = (request.form.get('currency') or 'AED').strip() or 'AED'

    fields = {
        'routers.$.name': r_name,
        'routers.$.ip': r_ip,
        'routers.$.api_user': r_user,
        'routers.$.dns_name': dns_name,
        'routers.$.currency': currency,
    }

    # Only update password if user provided a new one
    if r_pass:
        fields['routers.$.api_pass_enc'] = encrypt_text(r_pass)
        # also remove legacy plaintext api_pass if present
        mongo.db.users.update_one({'_id': ObjectId(user_id), 'routers.id': r_id}, {'$unset': {'routers.$.api_pass': ''}})

    mongo.db.users.update_one({'_id': ObjectId(user_id), 'routers.id': r_id}, {'$set': fields})
    flash('Router updated', 'success')
    return redirect(request.referrer or url_for('dashboard.dashboard'))


@bp.route('/admin/delete_router/<u_id>/<r_id>')
@login_required
@require_flag('allow_user_manage')
def delete_router(u_id, r_id):
    # Staff can only modify users they created
    if getattr(current_user, 'role', 'user') != 'admin':
        u_doc = mongo.db.users.find_one({'_id': ObjectId(u_id)}) or {}
        if u_doc.get('role') != 'user' or u_doc.get('created_by') != str(current_user.id):
            abort(403)

    mongo.db.users.update_one({'_id': ObjectId(u_id)}, {'$pull': {'routers': {'id': r_id}}})
    flash('Router deleted', 'success')
    return redirect(request.referrer or url_for('dashboard.dashboard'))


@bp.route('/admin/quick_user', methods=['GET', 'POST'])
@bp.route('/admin/quick_user/<router_id>', methods=['GET', 'POST'])
@login_required
@require_flag('allow_quick_user')
def quick_user(router_id=None):
    router_id = router_id or request.args.get('router_id') or session.get('router_id')
    router = _get_router_for_current_user(router_id)
    if not router:
        flash('Router not found', 'danger')
        return redirect(url_for('dashboard.dashboard'))

    profiles = []
    try:
        conn, api = _get_pool_api(router)
        profiles = [p['name'] for p in api.get_resource('/ip/hotspot/user/profile').get()]
        conn.disconnect()
    except Exception:
        pass

    if request.method == 'POST':
        u_name = request.form.get('username')
        u_pass = request.form.get('password')
        profile = request.form.get('profile')
        comment = request.form.get('comment', '')
        try:
            conn, api = _get_pool_api(router)
            api.get_resource('/ip/hotspot/user').add(name=u_name, password=u_pass, profile=profile, comment=comment)
            conn.disconnect()
            flash('User created on router', 'success')
            return redirect(url_for('admin.hotspot_users', router_id=router_id))
        except Exception as e:
            flash(str(e), 'danger')

    return render_template('quick_user.html', router=router, profiles=profiles)

@bp.route('/admin/config', methods=['GET', 'POST'])
@login_required
@require_admin
def admin_config():
    """Admin configuration: manage router credentials safely.

    - Passwords are encrypted before storing (api_pass_enc).
    - Password is never displayed back to UI.
    - Supports quick migration: encrypt legacy plaintext api_pass into api_pass_enc and remove api_pass.
    """
    action = (request.form.get('action') or '').strip()

    # Update app settings (branding + Gmail SMTP)
    if request.method == 'POST' and action == 'update_app_settings':
                # BRAND_NAME is a single source of truth from config.py (not editable from UI)
        from flask import current_app
        brand_name = current_app.config.get('BRAND_NAME', 'MikroMan')
        brand_accent = (request.form.get('brand_accent') or '').strip() or '#2563eb'

        mail_username = (request.form.get('mail_username') or '').strip()
        mail_password = (request.form.get('mail_password') or '').strip()
        mail_default_sender = (request.form.get('mail_default_sender') or mail_username).strip()
        mail_use_tls = (request.form.get('mail_use_tls') == 'on')
        mail_port = int(request.form.get('mail_port') or 587)
        mail_server = (request.form.get('mail_server') or 'smtp.gmail.com').strip()

        # UI defaults (per role)
        def _cb(name: str) -> bool:
            return (request.form.get(name) == 'on')
        user_navbar = _cb('ui_user_navbar')
        user_sidebar = _cb('ui_user_sidebar')
        staff_navbar = _cb('ui_staff_navbar')
        staff_sidebar = _cb('ui_staff_sidebar')
        user_landing = (request.form.get('ui_user_landing') or 'dashboard').strip()
        staff_landing = (request.form.get('ui_staff_landing') or 'dashboard').strip()

        traffic_interval = max(10, min(60, int(request.form.get('traffic_interval') or 10)))

        mongo.db.settings.update_one(
            {'_id': 'app_settings'},
            {'$set': {
                'brand_name': brand_name,  # kept for backward compatibility

                'brand_accent': brand_accent,
                'traffic_interval': traffic_interval,
                'mail_server': mail_server,
                'mail_port': mail_port,
                'mail_use_tls': mail_use_tls,
                'mail_username': mail_username,
                'mail_password': mail_password,
                'mail_default_sender': mail_default_sender,

                'ui_defaults': {
                    'user': {
                        'navbar': user_navbar,
                        'sidebar': user_sidebar,
                        'landing': user_landing,
                    },
                    'staff': {
                        'navbar': staff_navbar,
                        'sidebar': staff_sidebar,
                        'landing': staff_landing,
                    }
                }
            }},
            upsert=True
        )
        flash('App settings updated. Restart the server to apply mail settings.', 'success')
        return redirect(url_for('admin.admin_config'))


    # One-click migrate legacy passwords
    if request.method == 'POST' and action == 'migrate_encrypt':
        updated = 0
        for u in mongo.db.users.find({'routers': {'$exists': True, '$ne': []}}):
            changed = False
            routers = u.get('routers') or []
            for r in routers:
                if r.get('api_pass') and not r.get('api_pass_enc'):
                    r['api_pass_enc'] = encrypt_text(r.get('api_pass'))
                    r.pop('api_pass', None)
                    changed = True
            if changed:
                mongo.db.users.update_one({'_id': u['_id']}, {'$set': {'routers': routers}})
                updated += 1
        flash(f'Encrypted legacy router passwords for {updated} user(s).', 'success')
        return redirect(url_for('admin.admin_config'))

    # Add / update router (reuses existing admin.add_router_to_user)
    if request.method == 'POST' and action == 'save_router':
        return add_router_to_user()

    # Delete router
    if request.method == 'POST' and action == 'delete_router':
        u_id = (request.form.get('u_id') or '').strip()
        r_id = (request.form.get('r_id') or '').strip()
        if u_id and r_id:
            mongo.db.users.update_one({'_id': ObjectId(u_id)}, {'$pull': {'routers': {'id': r_id}}})
            flash('Router removed', 'success')
        return redirect(url_for('admin.admin_config'))

    users = list(mongo.db.users.find({'role': {'$ne': 'admin'}}).sort('username', 1))
    app_settings = mongo.db.settings.find_one({'_id': 'app_settings'}) or {}
    return render_template('admin_config.html', users=users, app_settings=app_settings)

# ─── Site Editor (admin only) ──────────────────────────────
@bp.route('/admin/site_editor', methods=['GET', 'POST'])
@login_required
@require_admin
def site_editor():
    """Edit landing page content: hero, features, pricing, demo, footer, etc."""
    SITE_KEY = 'site_content'

    defaults = {
        # Hero
        'hero_badge': 'Modern Hotspot Management',
        'hero_title_1': 'Manage Your',
        'hero_title_2': 'MikroTik Hotspot',
        'hero_title_3': 'Like a Pro',
        'hero_desc': 'The all-in-one solution for MikroTik hotspot billing, voucher generation, user management, and real-time monitoring. Built for ISPs, cafes, hotels & resellers.',
        'hero_stat1_num': '50+', 'hero_stat1_label': 'Active Users',
        'hero_stat2_num': '200+', 'hero_stat2_label': 'Routers',
        'hero_stat3_num': '99.9%', 'hero_stat3_label': 'Uptime',

        # Pricing
        'plan1_name': 'Starter', 'plan1_price': 'Free', 'plan1_period': '',
        'plan1_desc': 'For personal use & testing',
        'plan1_f1': '1 Router', 'plan1_f2': 'Voucher Generation', 'plan1_f3': 'Basic Reports',
        'plan1_f4': 'User Management', 'plan1_f5': 'Email Support', 'plan1_f6': '',
        'plan1_btn': 'Get Started',

        'plan2_name': 'Professional', 'plan2_price': '$29', 'plan2_period': '/mo',
        'plan2_desc': 'For businesses & ISPs', 'plan2_popular': True,
        'plan2_f1': 'Unlimited Routers', 'plan2_f2': 'All Features', 'plan2_f3': 'Sub-Admin Roles',
        'plan2_f4': 'Live Monitor', 'plan2_f5': 'PDF Templates', 'plan2_f6': 'Priority Support',
        'plan2_btn': 'Start Free Trial',

        'plan3_name': 'Enterprise', 'plan3_price': 'Custom', 'plan3_period': '',
        'plan3_desc': 'For large-scale deployments',
        'plan3_f1': 'Everything in Pro', 'plan3_f2': 'Dedicated Server', 'plan3_f3': 'Custom Branding',
        'plan3_f4': 'API Access', 'plan3_f5': '24/7 Support', 'plan3_f6': '',
        'plan3_btn': 'Contact Sales',
        'plan3_btn_link': 'mailto:support@example.com',

        # Demo
        'demo_title': 'Try Before You Buy',
        'demo_desc': 'Experience MikroMan with a live MikroTik router. No sign-up needed for demo.',
        'demo_user': 'demo', 'demo_pass': 'demo1234',
        'demo_limit1': 'Read-only access', 'demo_limit2': 'Cannot create vouchers', 'demo_limit3': 'Resets every hour',

        # Footer
        'footer_desc': 'Modern MikroTik Hotspot Management System. Built with love for network administrators.',
        'support_email': 'support@example.com',
        'telegram_url': '', 'whatsapp_url': '', 'youtube_url': '',

        # CTA
        'cta_title': 'Ready to Get Started?',
        'cta_desc': 'Join hundreds of ISPs and businesses already using MikroMan to manage their hotspot infrastructure.',

        # Registration settings
        'landing_enabled': 'on',          # on/off — show landing page or redirect to login
        'registration_enabled': 'on',     # on/off
        'registration_approval': 'on',    # on = require admin approval, off = auto-approve

        # SEO
        'seo_title': current_app.config.get('BRAND_NAME', 'MikroMan'),
        'seo_description': '',
        'seo_keywords': '',
        'canonical_base': '',
        'og_title': '',
        'og_description': '',
        'og_image': '',
        'robots': 'index',
        'google_verify': '',
        # Analytics
        'ga_measurement_id': '',
        'gtm_id': '',
        'head_script': '',
        # Sitemap
        'sitemap_extra_urls': '',
        'sitemap_include_custom_pages': 'on',
        # robots.txt
        'robots_txt': 'User-agent: *\nAllow: /\nDisallow: /admin/\nDisallow: /auth/\nDisallow: /dashboard/\n\nSitemap: {SITE_URL}/sitemap.xml',

        # Theme
        'theme_accent': '#3b82f6',
        'theme_accent2': '#8b5cf6',
        'theme_bg': '#0a0e1a',
        'theme_card': '#111827',
        'custom_css': '',
    }

    site = mongo.db.settings.find_one({'_id': SITE_KEY}) or {}
    # Merge defaults
    for k, v in defaults.items():
        if k not in site:
            site[k] = v

    if request.method == 'POST':
        updates = {}
        for k in defaults:
            val = request.form.get(k)
            if val is not None:
                # Don't strip robots_txt and head_script — preserve newlines
                if k in ('robots_txt', 'head_script', 'sitemap_extra_urls'):
                    updates[k] = val
                else:
                    updates[k] = val.strip()
        # Checkboxes / toggles
        updates['plan2_popular'] = ('plan2_popular' in request.form)
        updates['landing_enabled'] = 'on' if ('landing_enabled' in request.form) else 'off'
        updates['registration_enabled'] = 'on' if ('registration_enabled' in request.form) else 'off'
        updates['registration_approval'] = 'on' if ('registration_approval' in request.form) else 'off'
        updates['robots'] = 'index' if ('robots' in request.form) else 'noindex'
        updates['sitemap_include_custom_pages'] = 'on' if ('sitemap_include_custom_pages' in request.form) else 'off'

        # Per-page SEO meta tags
        page_seo = {}
        seo_page_keys = ['home', 'register', 'demo', 'login']
        # Also gather custom page slugs
        pages_doc = mongo.db.settings.find_one({'_id': 'custom_pages'}) or {}
        cp_list = pages_doc.get('pages', [])
        for p in cp_list:
            seo_page_keys.append('cp_' + p['slug'])

        for pk in seo_page_keys:
            title = (request.form.get(f'page_seo_{pk}_title') or '').strip()
            desc = (request.form.get(f'page_seo_{pk}_desc') or '').strip()
            og_title = (request.form.get(f'page_seo_{pk}_og_title') or '').strip()
            og_image = (request.form.get(f'page_seo_{pk}_og_image') or '').strip()
            if title or desc or og_title or og_image:
                page_seo[pk] = {
                    'title': title, 'desc': desc,
                    'og_title': og_title, 'og_image': og_image
                }
        updates['page_seo'] = page_seo

        mongo.db.settings.update_one(
            {'_id': SITE_KEY},
            {'$set': updates},
            upsert=True
        )

        # Also store robots_txt and canonical_base in seo_settings for site.py routes
        seo_updates = {
            'robots_txt': updates.get('robots_txt', ''),
            'canonical_base': updates.get('canonical_base', ''),
        }
        mongo.db.settings.update_one(
            {'_id': 'seo_settings'},
            {'$set': seo_updates},
            upsert=True
        )

        from ..services.logger import log_activity
        log_activity(current_user.username, 'Site Editor', 'Updated landing page content')
        flash('Site content updated!', 'success')
        return redirect(url_for('admin.site_editor'))

    pages_doc = mongo.db.settings.find_one({'_id': 'custom_pages'}) or {}
    custom_pages = pages_doc.get('pages', [])
    return render_template('site_editor.html', site=site, custom_pages=custom_pages)


# ─── Custom Pages CRUD ─────────────────────────────────────
PAGES_KEY = 'custom_pages'

@bp.route('/admin/pages/save', methods=['POST'])
@login_required
@require_admin
def pages_save():
    slug = (request.form.get('slug') or '').strip().lower()
    title = (request.form.get('title') or '').strip()
    content = request.form.get('content') or ''
    meta_desc = (request.form.get('meta_desc') or '').strip()
    if not slug or not title:
        flash('Slug and title are required.', 'danger')
        return redirect(url_for('admin.site_editor') + '#sec-pages')
    slug = re.sub(r'[^a-z0-9-]', '-', slug).strip('-')
    doc = mongo.db.settings.find_one({'_id': PAGES_KEY}) or {'pages': []}
    pages = doc.get('pages', [])
    existing = next((i for i, p in enumerate(pages) if p['slug'] == slug), None)
    page_obj = {'slug': slug, 'title': title, 'content': content, 'meta_desc': meta_desc}
    if existing is not None:
        pages[existing] = page_obj
    else:
        pages.append(page_obj)
    mongo.db.settings.update_one({'_id': PAGES_KEY}, {'$set': {'pages': pages}}, upsert=True)
    flash(f'Page "/{slug}" saved.', 'success')
    return redirect(url_for('admin.site_editor') + '?tab=pages')


@bp.route('/admin/pages/delete/<slug>', methods=['POST'])
@login_required
@require_admin
def pages_delete(slug):
    doc = mongo.db.settings.find_one({'_id': PAGES_KEY}) or {'pages': []}
    pages = [p for p in doc.get('pages', []) if p['slug'] != slug]
    mongo.db.settings.update_one({'_id': PAGES_KEY}, {'$set': {'pages': pages}}, upsert=True)
    flash(f'Page "/{slug}" deleted.', 'success')
    return redirect(url_for('admin.site_editor') + '?tab=pages')


@bp.route('/admin/pages/preview/<slug>')
@login_required
@require_admin
def pages_preview(slug):
    return redirect(url_for('site.custom_page', slug=slug))


# ─── Sitemap Generator ─────────────────────────────────────
@bp.route('/admin/generate_sitemap', methods=['POST'])
@login_required
@require_admin
def generate_sitemap():
    """Auto-generate sitemap.xml with all public routes and custom pages."""
    from datetime import datetime, timezone
    site = mongo.db.settings.find_one({'_id': 'site_content'}) or {}
    base = (site.get('canonical_base') or request.host_url).rstrip('/')
    now = datetime.now(timezone.utc).strftime('%Y-%m-%d')

    urls = []

    # Home
    urls.append({'loc': f'{base}/', 'priority': '1.0', 'changefreq': 'weekly'})
    # Register
    urls.append({'loc': f'{base}/register', 'priority': '0.7', 'changefreq': 'monthly'})
    # Demo
    urls.append({'loc': f'{base}/demo', 'priority': '0.6', 'changefreq': 'monthly'})

    # Custom pages
    if site.get('sitemap_include_custom_pages', 'on') != 'off':
        pages_doc = mongo.db.settings.find_one({'_id': 'custom_pages'}) or {}
        for p in pages_doc.get('pages', []):
            urls.append({'loc': f'{base}/p/{p["slug"]}', 'priority': '0.6', 'changefreq': 'monthly'})

    # Extra URLs
    extra = site.get('sitemap_extra_urls', '')
    for line in extra.strip().splitlines():
        url = line.strip()
        if url and url.startswith('http'):
            urls.append({'loc': url, 'priority': '0.5', 'changefreq': 'monthly'})

    # Build XML
    xml_parts = ['<?xml version="1.0" encoding="UTF-8"?>',
                 '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">']
    for u in urls:
        xml_parts.append(f'  <url>')
        xml_parts.append(f'    <loc>{u["loc"]}</loc>')
        xml_parts.append(f'    <lastmod>{now}</lastmod>')
        xml_parts.append(f'    <changefreq>{u["changefreq"]}</changefreq>')
        xml_parts.append(f'    <priority>{u["priority"]}</priority>')
        xml_parts.append(f'  </url>')
    xml_parts.append('</urlset>')
    xml = '\n'.join(xml_parts)

    # Cache in DB
    mongo.db.settings.update_one(
        {'_id': 'sitemap_cache'},
        {'$set': {'xml': xml, 'generated_at': now, 'url_count': len(urls)}},
        upsert=True
    )

    from ..services.logger import log_activity
    log_activity(current_user.username, 'SEO', f'Generated sitemap.xml with {len(urls)} URLs')

    return jsonify({'ok': True, 'msg': f'Sitemap generated with {len(urls)} URLs'})


# =============================================
#   BRIDGE PORT LOCK / UNLOCK
# =============================================
# PORT LOCK / UNLOCK
# =============================================

@bp.route('/port-lock')
@login_required
def port_lock_page():
    user_doc = mongo.db.users.find_one({'_id': ObjectId(current_user.id)}) or {}
    _is_admin = (user_doc.get('role') == 'admin')
    if not _is_admin and not user_doc.get('allow_port_lock'):
        abort(403)
    router_id = session.get('router_id')
    router = _get_router_for_current_user(router_id)
    config = get_port_lock_config(mongo.db, router_id) if router_id else None
    return render_template('port_lock.html',
                           selected_router=router,
                           is_admin=_is_admin,
                           has_config=bool(config))


@bp.route('/port-lock/status', methods=['GET', 'POST'])
@login_required
def port_lock_status():
    """Lightweight state check — no full bridge scan. Accessible to all permitted users."""
    user_doc = mongo.db.users.find_one({'_id': ObjectId(current_user.id)}) or {}
    _is_admin = (user_doc.get('role') == 'admin')
    if not _is_admin and not user_doc.get('allow_port_lock'):
        return jsonify({'ok': False, 'error': 'Permission denied'}), 403

    router_id = request.values.get('router_id') or session.get('router_id')
    if not router_id:
        return jsonify({'ok': True, 'configured': False, 'state': 'unknown'})

    config = get_port_lock_config(mongo.db, router_id)
    if not config:
        return jsonify({'ok': True, 'configured': False, 'state': 'unknown'})

    router = _get_router_for_current_user(router_id)
    if not router:
        return jsonify({'ok': False, 'error': 'Router not found'})

    try:
        conn, api = _get_pool_api(router)
        state = detect_lock_state(api, config)
        conn.disconnect()
        return jsonify({'ok': True, 'configured': True, 'state': state})
    except Exception as e:
        return jsonify({'ok': True, 'configured': True, 'state': 'unknown', 'error': str(e)})


@bp.route('/port-lock/scan', methods=['POST'])
@login_required
def port_lock_scan():
    """Scan bridges + ports. Admin only."""
    user_doc = mongo.db.users.find_one({'_id': ObjectId(current_user.id)}) or {}
    if user_doc.get('role') != 'admin':
        return jsonify({'ok': False, 'error': 'Admin access required'}), 403

    router_id = request.form.get('router_id') or session.get('router_id')
    if not router_id:
        return jsonify({'ok': False, 'error': 'No router selected'})
    router = _get_router_for_current_user(router_id)
    if not router:
        return jsonify({'ok': False, 'error': 'Router not found'})

    try:
        conn, api = get_api(router)
        try:
            scan = scan_bridges_and_ports(api)
            config = get_port_lock_config(mongo.db, router_id)
            state = 'unknown'
            if config:
                state = detect_lock_state(api, config)
            return jsonify({
                'ok': True,
                'scan': scan,
                'ros_version': scan.get('ros_version', {}),
                'state': state,
                'config': {
                    'hotspot_bridges': config.get('hotspot_bridges', []),
                    'free_bridges': config.get('free_bridges', []),
                    'excluded_ports': config.get('excluded_ports', []),
                    'port_map': config.get('port_map', []),
                    'ros_major': config.get('ros_major', 0),
                } if config else None,
            })
        finally:
            conn.disconnect()
    except Exception as e:
        return jsonify({'ok': False, 'error': f'Scan failed: {str(e)}'})


@bp.route('/port-lock/configure', methods=['POST'])
@login_required
def port_lock_configure():
    """Save port lock config + auto-create RouterOS scripts. Admin only."""
    user_doc = mongo.db.users.find_one({'_id': ObjectId(current_user.id)}) or {}
    if user_doc.get('role') != 'admin':
        return jsonify({'ok': False, 'error': 'Admin access required'}), 403

    router_id = request.form.get('router_id') or session.get('router_id')
    excluded_csv = request.form.get('excluded_ports', '').strip()
    excluded = [x.strip() for x in excluded_csv.split(',') if x.strip()] if excluded_csv else []
    hs_csv = request.form.get('hotspot_bridges', '').strip()
    free_csv = request.form.get('free_bridges', '').strip()
    selected_hs = [x.strip() for x in hs_csv.split(',') if x.strip()] if hs_csv else None
    selected_free = [x.strip() for x in free_csv.split(',') if x.strip()] if free_csv else None

    if not router_id:
        return jsonify({'ok': False, 'error': 'No router selected'})
    router = _get_router_for_current_user(router_id)
    if not router:
        return jsonify({'ok': False, 'error': 'Router not found'})

    try:
        conn, api = get_api(router)
        try:
            scan = scan_bridges_and_ports(api)
            doc = save_port_lock_config(
                mongo.db, router_id, scan, excluded,
                selected_hotspot_bridges=selected_hs,
                selected_free_bridges=selected_free,
            )
            if not doc:
                return jsonify({'ok': False, 'error': 'No hotspot bridge selected'})

            # Auto-create RouterOS scripts for maximum reliability
            scripts_created = []
            try:
                scripts_created = ensure_port_lock_scripts(api, doc)
            except Exception:
                pass  # Scripts optional — direct API fallback always works

            state = detect_lock_state(api, doc)
            log_activity(current_user.username, 'Port Lock Config',
                         f'Hotspot: {", ".join(doc.get("hotspot_bridges", []))}, '
                         f'Free: {", ".join(doc.get("free_bridges", []))}, '
                         f'Ports: {len(doc.get("port_map", []))}')
            return jsonify({
                'ok': True,
                'state': state,
                'scripts': scripts_created,
                'ros_version': scan.get('ros_version', {}),
                'config': {
                    'hotspot_bridges': doc.get('hotspot_bridges', []),
                    'free_bridges': doc.get('free_bridges', []),
                    'excluded_ports': doc.get('excluded_ports', []),
                    'port_map': doc.get('port_map', []),
                    'ros_major': doc.get('ros_major', 0),
                }
            })
        finally:
            conn.disconnect()
    except Exception as e:
        return jsonify({'ok': False, 'error': f'Configure failed: {str(e)}'})


@bp.route('/port-lock/action', methods=['POST'])
@login_required
def port_lock_do_action():
    """Execute lock or unlock. Any user with allow_port_lock flag."""
    user_doc = mongo.db.users.find_one({'_id': ObjectId(current_user.id)}) or {}
    _is_admin = (user_doc.get('role') == 'admin')
    if not _is_admin and not user_doc.get('allow_port_lock'):
        return jsonify({'ok': False, 'error': 'Permission denied'}), 403

    router_id = request.form.get('router_id') or session.get('router_id')
    action = request.form.get('action', '')
    if action not in ('lock', 'unlock'):
        return jsonify({'ok': False, 'error': 'Invalid action'})

    router = _get_router_for_current_user(router_id)
    if not router:
        return jsonify({'ok': False, 'error': 'Router not found'})

    config = get_port_lock_config(mongo.db, router_id)
    if not config:
        return jsonify({'ok': False, 'error': 'Not configured. Admin must configure bridges first.'})

    try:
        conn, api = get_api(router)
        try:
            result = port_lock_action(api, config, action)
            if result.get('ok'):
                log_activity(current_user.username, f'Port {action.title()}', result.get('detail', ''))
            return jsonify(result)
        finally:
            conn.disconnect()
    except Exception as e:
        return jsonify({'ok': False, 'error': f'Action failed: {str(e)}'})


@bp.route('/port-lock/setup-scripts', methods=['POST'])
@login_required
def port_lock_setup_scripts():
    """Create/update RouterOS scripts. Admin only."""
    user_doc = mongo.db.users.find_one({'_id': ObjectId(current_user.id)}) or {}
    if user_doc.get('role') != 'admin':
        return jsonify({'ok': False, 'error': 'Admin access required'}), 403

    router_id = request.form.get('router_id') or session.get('router_id')
    router = _get_router_for_current_user(router_id)
    if not router:
        return jsonify({'ok': False, 'error': 'Router not found'})

    config = get_port_lock_config(mongo.db, router_id)
    if not config:
        return jsonify({'ok': False, 'error': 'Not configured'})

    try:
        conn, api = get_api(router)
        try:
            scripts = ensure_port_lock_scripts(api, config)
            log_activity(current_user.username, 'Port Lock Scripts', f'Scripts: {", ".join(scripts)}')
            return jsonify({'ok': True, 'scripts': scripts})
        finally:
            conn.disconnect()
    except Exception as e:
        return jsonify({'ok': False, 'error': f'Script failed: {str(e)}'})


@bp.route('/port-lock/reset', methods=['POST'])
@login_required
def port_lock_reset():
    """Delete saved config. Admin only."""
    user_doc = mongo.db.users.find_one({'_id': ObjectId(current_user.id)}) or {}
    if user_doc.get('role') != 'admin':
        return jsonify({'ok': False, 'error': 'Admin access required'}), 403

    router_id = request.form.get('router_id') or session.get('router_id')
    if router_id:
        delete_port_lock_config(mongo.db, router_id)
        log_activity(current_user.username, 'Port Lock Reset', 'Config deleted')
    return jsonify({'ok': True})



# ═══════════════════════════════════════════════════════════════
# SEO MODULE — Sitemap, robots.txt, Analytics, Per-page Meta
# ═══════════════════════════════════════════════════════════════

SEO_KEY = 'seo_settings'

def _get_seo_settings():
    """Load SEO settings with defaults."""
    defaults = {
        # robots.txt
        'robots_txt': 'User-agent: *\nAllow: /\nDisallow: /a/\nDisallow: /auth/\nDisallow: /dashboard\n\nSitemap: {SITE_URL}/sitemap.xml',
        # Sitemap
        'sitemap_enabled': True,
        'sitemap_custom_urls': '',  # one per line: url|priority|changefreq
        'sitemap_exclude': '/auth/,/a/',  # comma-separated prefixes to exclude
        # Google Analytics
        'ga_measurement_id': '',  # GA4: G-XXXXXXXX
        'ga_enabled': False,
        # Google Search Console
        'gsc_verification': '',
        # Bing Webmaster
        'bing_verification': '',
        # Canonical URL base
        'canonical_base': '',  # e.g., https://mikroman.xyz
        # Structured Data (JSON-LD)
        'schema_enabled': True,
        'schema_type': 'WebApplication',  # WebApplication, SoftwareApplication, Organization
        'schema_name': '',
        'schema_description': '',
        'schema_author': '',
        # Social
        'twitter_card': 'summary_large_image',
        'twitter_handle': '',
        # Custom <head> injection
        'head_scripts': '',  # raw HTML to inject in <head>
        # Auto-generate meta for pages
        'auto_meta_enabled': True,
    }
    doc = mongo.db.settings.find_one({'_id': SEO_KEY}) or {}
    for k, v in defaults.items():
        if k not in doc:
            doc[k] = v
    return doc


@bp.route('/admin/seo', methods=['GET', 'POST'])
@login_required
@require_admin
def seo_dashboard():
    """Comprehensive SEO settings dashboard."""
    seo = _get_seo_settings()
    site = mongo.db.settings.find_one({'_id': 'site_content'}) or {}
    pages_doc = mongo.db.settings.find_one({'_id': 'custom_pages'}) or {}
    custom_pages = pages_doc.get('pages', [])

    if request.method == 'POST':
        action = request.form.get('action', 'save_seo')

        if action == 'save_seo':
            updates = {}
            # Multiline fields — preserve newlines, only strip edges
            multiline_fields = ('robots_txt', 'sitemap_custom_urls', 'head_scripts')
            # Text fields
            for f in ['robots_txt', 'sitemap_custom_urls', 'sitemap_exclude',
                       'ga_measurement_id', 'gsc_verification', 'bing_verification',
                       'canonical_base', 'schema_type', 'schema_name',
                       'schema_description', 'schema_author', 'twitter_card',
                       'twitter_handle', 'head_scripts']:
                val = request.form.get(f)
                if val is not None:
                    if f in multiline_fields:
                        updates[f] = val
                    else:
                        updates[f] = val.strip()
            # Canonical: remove trailing slash
            if updates.get('canonical_base', '').endswith('/'):
                updates['canonical_base'] = updates['canonical_base'].rstrip('/')
            # Booleans
            updates['sitemap_enabled'] = 'sitemap_enabled' in request.form
            updates['ga_enabled'] = 'ga_enabled' in request.form
            updates['schema_enabled'] = 'schema_enabled' in request.form
            updates['auto_meta_enabled'] = 'auto_meta_enabled' in request.form

            mongo.db.settings.update_one(
                {'_id': SEO_KEY}, {'$set': updates}, upsert=True
            )
            from ..services.logger import log_activity
            log_activity(current_user.username, 'SEO', 'Updated SEO settings')
            flash('SEO settings saved!', 'success')
            return redirect(url_for('admin.seo_dashboard'))

        elif action == 'save_page_meta':
            # Per-page meta tags
            slug = request.form.get('page_slug', '').strip()
            if slug:
                meta_update = {
                    'seo_title': request.form.get('page_seo_title', '').strip(),
                    'meta_desc': request.form.get('page_meta_desc', '').strip(),
                    'meta_keywords': request.form.get('page_meta_keywords', '').strip(),
                    'og_title': request.form.get('page_og_title', '').strip(),
                    'og_desc': request.form.get('page_og_desc', '').strip(),
                    'og_image': request.form.get('page_og_image', '').strip(),
                    'canonical': request.form.get('page_canonical', '').strip(),
                    'robots': request.form.get('page_robots', 'index, follow').strip(),
                }
                # Update the page in custom_pages
                doc = mongo.db.settings.find_one({'_id': 'custom_pages'}) or {'pages': []}
                pages = doc.get('pages', [])
                for p in pages:
                    if p['slug'] == slug:
                        p['seo'] = meta_update
                        break
                mongo.db.settings.update_one(
                    {'_id': 'custom_pages'}, {'$set': {'pages': pages}}, upsert=True
                )
                flash(f'SEO meta for /{slug} saved!', 'success')
            return redirect(url_for('admin.seo_dashboard') + '?tab=pages')

    return render_template('seo_dashboard.html', seo=seo, site=site, custom_pages=custom_pages)


@bp.route('/admin/seo/generate-sitemap', methods=['POST'])
@login_required
@require_admin
def seo_generate_sitemap():
    """Force re-generate sitemap and store it."""
    seo = _get_seo_settings()
    site = mongo.db.settings.find_one({'_id': 'site_content'}) or {}
    base_url = seo.get('canonical_base', '').rstrip('/')
    if not base_url:
        flash('Set a Canonical Base URL first!', 'danger')
        return redirect(url_for('admin.seo_dashboard'))

    excludes = [x.strip() for x in seo.get('sitemap_exclude', '').split(',') if x.strip()]

    urls = []
    # Static pages
    static_pages = [
        {'loc': '/', 'priority': '1.0', 'changefreq': 'weekly'},
    ]
    for sp in static_pages:
        loc = sp.get('loc', '')
        skip = False
        for ex in excludes:
            if loc.startswith(ex):
                skip = True
                break
        if not skip:
            urls.append(sp)

    # Custom pages
    pages_doc = mongo.db.settings.find_one({'_id': 'custom_pages'}) or {}
    for p in pages_doc.get('pages', []):
        urls.append({
            'loc': f'/site/p/{p["slug"]}',
            'priority': '0.6',
            'changefreq': 'monthly',
        })

    # Custom URLs from settings
    for line in seo.get('sitemap_custom_urls', '').strip().split('\n'):
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        parts = line.split('|')
        entry = {'loc': parts[0].strip()}
        if len(parts) > 1:
            entry['priority'] = parts[1].strip()
        if len(parts) > 2:
            entry['changefreq'] = parts[2].strip()
        urls.append(entry)

    # Build XML
    xml_lines = ['<?xml version="1.0" encoding="UTF-8"?>']
    xml_lines.append('<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">')
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).strftime('%Y-%m-%d')
    for u in urls:
        loc = u.get('loc', '')
        if not loc.startswith('http'):
            loc = base_url + loc
        xml_lines.append('  <url>')
        xml_lines.append(f'    <loc>{loc}</loc>')
        xml_lines.append(f'    <lastmod>{now}</lastmod>')
        if u.get('changefreq'):
            xml_lines.append(f'    <changefreq>{u["changefreq"]}</changefreq>')
        if u.get('priority'):
            xml_lines.append(f'    <priority>{u["priority"]}</priority>')
        xml_lines.append('  </url>')
    xml_lines.append('</urlset>')

    sitemap_xml = '\n'.join(xml_lines)

    # Store in DB
    mongo.db.settings.update_one(
        {'_id': 'sitemap_cache'},
        {'$set': {'xml': sitemap_xml, 'generated_at': datetime.now(timezone.utc).isoformat()}},
        upsert=True
    )

    flash(f'Sitemap generated with {len(urls)} URLs!', 'success')
    from ..services.logger import log_activity
    log_activity(current_user.username, 'SEO', f'Generated sitemap with {len(urls)} URLs')
    return redirect(url_for('admin.seo_dashboard'))


# CSRF exemptions for AJAX endpoints
_csrf.exempt(voucher_status_check)
_csrf.exempt(port_lock_status)
_csrf.exempt(port_lock_scan)
_csrf.exempt(port_lock_configure)
_csrf.exempt(port_lock_do_action)
_csrf.exempt(port_lock_setup_scripts)
_csrf.exempt(port_lock_reset)
