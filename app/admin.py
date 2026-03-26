import io
import os
import random
import re
import threading
from bson.objectid import ObjectId
from datetime import datetime
from flask import Blueprint, render_template, request, redirect, url_for, flash, send_file
from flask_login import login_required, current_user, login_user
from jinja2.sandbox import SandboxedEnvironment

_sandbox_env = SandboxedEnvironment()

def _safe_render_voucher(template_html: str, context: dict) -> str:
    try:
        tpl = _sandbox_env.from_string(template_html)
        return tpl.render(**context)
    except Exception:
        return f"<div>User: {context.get('username', '?')}</div>"
from werkzeug.security import generate_password_hash

from ..extensions import mongo
from ..models.user import User
from ..services.mikrotik import get_api
from ..services.pdf_service import html_to_pdf_bytes
from ..services.logger import log_activity
from ..utils.helpers import generate_random_string
from ..utils.parsing import parse_activation_log
from ..utils.permissions import require_admin, require_flag, require_any
from ..utils.crypto import encrypt_text

bp = Blueprint('admin', __name__)

hotspot_lock = threading.Lock()

@bp.route('/create-vouchers')
@login_required
def create_vouchers_page():
    user_data = mongo.db.users.find_one({'_id': ObjectId(current_user.id)})
    routers = user_data.get('routers', []) if user_data else []
    selected_id = request.args.get('router_id')
    router = next((r for r in routers if r.get('id') == selected_id), None)
    if not router:
        flash('Notification: No router selected from dashboard!', 'warning')
        return redirect(url_for('dashboard.dashboard'))

    profiles = []
    try:
        conn, api = get_api(router)
        profiles = [p['name'] for p in api.get_resource('/ip/hotspot/user/profile').get()]
        conn.disconnect()
    except Exception as e:
        flash(f'Router Connection Error: {str(e)}', 'danger')

    return render_template('voucher.html', user_data=user_data, profiles=profiles, selected_router=router)

@bp.route('/api/get_profile_details/<router_id>/<profile_name>')
@login_required
def get_profile_details(router_id, profile_name):
    user_data = mongo.db.users.find_one({'_id': ObjectId(current_user.id)})
    router = next((r for r in user_data.get('routers', []) if r.get('id') == router_id), None)
    if not router:
        return {'error': 'Router not found'}, 404

    try:
        conn, api = get_api(router)
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

@bp.route('/admin/generate_hotspot', methods=['POST'])
@login_required
@require_flag('can_generate')
def generate_hotspot():
    user_role = getattr(current_user, 'role', 'user')

    try:
        qty = int(request.form.get('qty', 1))
    except Exception:
        qty = 1
    if user_role != 'admin' and qty > 200:
        flash('সাধারণ ইউজার হিসেবে আপনি একবারে সর্বোচ্চ ২০০টি ভাউচার করতে পারবেন।', 'danger')
        return redirect(url_for('dashboard.dashboard'))

    form_token = request.form.get('token')
    last_token = mongo.db.settings.find_one({'type': 'last_gen_token'})
    if last_token and last_token.get('token') == form_token:
        return redirect(url_for('dashboard.dashboard'))

    if not hotspot_lock.acquire(blocking=False):
        flash('আরেকটি জেনারেশন চলছে, কিছুক্ষণ অপেক্ষা করুন...', 'warning')
        return redirect(url_for('dashboard.dashboard'))

    try:
        mongo.db.settings.update_one({'type': 'last_gen_token'}, {'$set': {'token': form_token}}, upsert=True)

        router_id = request.form.get('router_id')
        branding = request.form.get('branding_name', 'My Hotspot')
        validity = request.form.get('timelimit', '30d')
        price = request.form.get('price', '0.00')
        profile = request.form.get('profile', 'default')
        user_mode = request.form.get('user_mode', 'up')
        user_l = int(request.form.get('user_length', 6))
        char_mode = request.form.get('char_mode', 'mix')

        now = datetime.now()
        curr_date = now.strftime('%d-%b-%Y')
        curr_time = now.strftime('%I:%M %p')

        user_with_router = mongo.db.users.find_one({'routers.id': router_id})
        router = next((r for r in user_with_router.get('routers', []) if r.get('id') == router_id), None)
        if not router:
            flash('Router not found!', 'danger')
            return redirect(url_for('dashboard.dashboard'))

        conn, api = get_api(router)
        res = api.get_resource('/ip/hotspot/user')

        vouchers_list = []
        for i in range(qty):
            u_name = generate_random_string(user_l, char_mode)
            u_pass = u_name if user_mode == 'vc' else generate_random_string(user_l, char_mode)
            try:
                res.add(name=u_name, password=u_pass, profile=profile, comment=f'Gen: {curr_date}')
                vouchers_list.append({
                    'hotspotname': branding,
                    'username': u_name,
                    'password': u_pass,
                    'validity': validity,
                    'timelimit': validity,
                    'price': price,
                    'profile': profile,
                    'date': curr_date,
                    'time': curr_time,
                    'num': i + 1,
                    'router_name': router.get('name', 'MikroTik'),
                    'dnsname': router.get('dns_name', 'login.net')
                })
            except Exception:
                continue
        conn.disconnect()

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
        return send_file(pdf_io, as_attachment=True, download_name=f"Vouchers_{now.strftime('%d%m%Y_%H%M%S')}.pdf", mimetype='application/pdf')

    except Exception as e:
        flash(f'Error: {str(e)}', 'danger')
        return redirect(url_for('dashboard.dashboard'))
    finally:
        try:
            hotspot_lock.release()
        except RuntimeError:
            pass  # Lock was not held by this thread

@bp.route('/hotspot/users/<router_id>')
@login_required
def hotspot_users(router_id):
    user_with_router = mongo.db.users.find_one({'routers.id': router_id})
    router = next((r for r in user_with_router.get('routers', []) if r.get('id') == router_id), None)
    if not router:
        flash('Router not found', 'danger')
        return redirect(url_for('dashboard.dashboard'))

    profile_filter = request.args.get('profile', '')
    comment_filter = request.args.get('comment', '')

    try:
        conn, api = get_api(router)
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


@bp.route('/hotspot/toggle_user/<router_id>/<user_id>/<action>')
@login_required
def toggle_hotspot_user(router_id, user_id, action):
    user_with_router = mongo.db.users.find_one({'routers.id': router_id})
    router = next((r for r in user_with_router.get('routers', []) if r.get('id') == router_id), None)
    if not router:
        return redirect(url_for('dashboard.dashboard'))
    status = 'yes' if action == 'disable' else 'no'
    try:
        conn, api = get_api(router)
        api.get_resource('/ip/hotspot/user').set(id=user_id, disabled=status)
        conn.disconnect()
        flash(f'User {action}d successfully!', 'success')
    except Exception as e:
        flash(str(e), 'danger')
    return redirect(request.referrer or url_for('admin.hotspot_users', router_id=router_id))

@bp.route('/hotspot/edit_user', methods=['POST'])
@login_required
def edit_hotspot_user():
    router_id = request.form.get('router_id')
    user_id = request.form.get('user_id')
    new_name = request.form.get('u_name')
    new_pass = request.form.get('u_pass')
    new_profile = request.form.get('u_profile')
    new_comment = request.form.get('u_comment')

    user_data = mongo.db.users.find_one({'_id': ObjectId(current_user.id)})
    router = next((r for r in user_data.get('routers', []) if r.get('id') == router_id), None)
    if router:
        try:
            conn, api = get_api(router)
            api.get_resource('/ip/hotspot/user').set(id=user_id, name=new_name, password=new_pass, profile=new_profile, comment=new_comment)
            conn.disconnect()
            flash(f'User {new_name} updated successfully!', 'success')
        except Exception as e:
            flash(f'Error: {str(e)}', 'danger')
    return redirect(request.referrer or url_for('admin.hotspot_users', router_id=router_id))


@bp.route('/hotspot/delete_user/<router_id>/<user_id>')
@login_required
def delete_hotspot_user(router_id, user_id):
    user_data = mongo.db.users.find_one({'_id': ObjectId(current_user.id)})
    router = next((r for r in user_data.get('routers', []) if r.get('id') == router_id), None)
    if router:
        try:
            conn, api = get_api(router)
            api.get_resource('/ip/hotspot/user').remove(id=user_id)
            conn.disconnect()
            flash('User deleted successfully!', 'info')
        except Exception as e:
            flash(str(e), 'danger')
    return redirect(request.referrer or url_for('admin.hotspot_users', router_id=router_id))

@bp.route('/admin/export_selected_pdf', methods=['POST'])
@login_required
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

    router = next((r for r in user_data.get('routers', []) if r.get('id') == router_id), None)
    if not router:
        flash('Router not found!', 'danger')
        return redirect(request.referrer or url_for('dashboard.dashboard'))

    vouchers = []
    try:
        conn, api = get_api(router)
        res = api.get_resource('/ip/hotspot/user')
        for idx, u_id in enumerate(selected_ids):
            u = res.get(id=u_id)
            if u:
                vouchers.append({
                    'hotspotname': router.get('name','Hotspot'),
                    'username': u[0].get('name'),
                    'password': u[0].get('password'),
                    'profile': u[0].get('profile'),
                    'num': idx + 1,
                    'dnsname': router.get('dns_name', 'login.net')
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
def sales_report():
    user_data = mongo.db.users.find_one({'_id': ObjectId(current_user.id)})
    if current_user.role != 'admin' and not user_data.get('allow_reports'):
        flash('আপনার রিপোর্ট দেখার অনুমতি নেই।', 'danger')
        return redirect(url_for('dashboard.dashboard'))

    user_routers = user_data.get('routers', [])
    router_id = request.args.get('router_id')
    if not router_id:
        return render_template('reports.html', select_router=True, routers=user_routers)

    router = next((r for r in user_routers if r.get('id') == router_id), None)
    if not router:
        return render_template('reports.html', select_router=True, routers=user_routers)

    selected_month = request.args.get('month', datetime.now().strftime('%Y-%m'))
    report_data, report_map, total_rev = [], {}, 0.0

    try:
        conn, api = get_api(router)
        scripts = api.get_resource('/system/script').get()
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
                total_rev += parsed['price']
                report_data.append(parsed)
                report_map[parsed['date']] = report_map.get(parsed['date'], 0) + parsed['price']

        labels = sorted(report_map.keys(), key=lambda x: datetime.strptime(x, '%b/%d/%Y'))
        stats = [report_map[d] for d in labels]

        return render_template('reports.html', labels=labels, stats=stats, total_rev=total_rev, report_data=report_data, selected_router=router, selected_month=selected_month)
    except Exception as e:
        flash(f'Error: {str(e)}', 'danger')
        return redirect(url_for('admin.sales_report'))

@bp.route('/admin/monitor/<router_id>')
@login_required
def monitor_router(router_id):
    user_with_router = mongo.db.users.find_one({'routers.id': router_id})
    if not user_with_router:
        return 'Router not found', 404
    router = next((r for r in user_with_router.get('routers', []) if r.get('id') == router_id), None)
    try:
        conn, api = get_api(router)
        active_users = api.get_resource('/ip/hotspot/active').get()
        interfaces = api.get_resource('/interface').get()
        conn.disconnect()
        return render_template('monitor.html', router=router, active_users=active_users, interfaces=interfaces)
    except Exception as e:
        flash(f'Connection Error: {str(e)}', 'danger')
        return redirect(url_for('dashboard.dashboard'))


@bp.route('/admin/kick_user/<router_id>/<active_id>')
@login_required
def kick_user(router_id, active_id):
    user_with_router = mongo.db.users.find_one({'routers.id': router_id})
    router = next((r for r in user_with_router.get('routers', []) if r.get('id') == router_id), None)
    try:
        conn, api = get_api(router)
        api.get_resource('/ip/hotspot/active').remove(id=active_id)
        conn.disconnect()
        flash('User disconnected successfully!', 'success')
    except Exception as e:
        flash(str(e), 'danger')
    return redirect(url_for('admin.monitor_router', router_id=router_id))


@bp.route('/api/traffic/<router_id>/<interface_name>')
@login_required
def get_traffic(router_id, interface_name):
    user_with_router = mongo.db.users.find_one({'routers.id': router_id})
    router = next((r for r in user_with_router.get('routers', []) if r.get('id') == router_id), None)
    try:
        conn, api = get_api(router)
        stats = api.get_resource('/interface').call('monitor-traffic', {'interface': interface_name, 'once': ''})
        conn.disconnect()
        return {'rx': stats[0].get('rx-bits-per-second', 0), 'tx': stats[0].get('tx-bits-per-second', 0)}
    except Exception:
        return {'rx': 0, 'tx': 0}


@bp.route('/reset_mac', methods=['POST'])
@login_required
def reset_mac():
    target = (request.form.get('h_user') or '').strip()
    router_id = (request.form.get('router_id') or '').strip()

    if not target or not router_id:
        flash('Missing user/router info!', 'warning')
        return redirect(url_for('dashboard.dashboard'))

    user_data = mongo.db.users.find_one({'_id': ObjectId(current_user.id)}) or {}
    router = next((r for r in user_data.get('routers', []) if r.get('id') == router_id), None)
    if not router:
        flash('Router not found!', 'danger')
        return redirect(url_for('dashboard.dashboard'))

    conn = None

    # Prevent concurrent Mikrotik API calls (reduces "!empty" / malformed issues)
    with hotspot_lock:
        try:
            conn, api = get_api(router)

            users_res = api.get_resource('/ip/hotspot/user')
            u = users_res.get(name=target) or []
            if not u:
                flash(f'Voucher/User not found: {target}', 'warning')
                return redirect(url_for('dashboard.dashboard'))

            user_id = u[0].get('id') or u[0].get('.id')
            if not user_id:
                flash('Could not resolve hotspot user id', 'danger')
                return redirect(url_for('dashboard.dashboard'))

            # RouterOS on your device requires a MAC value (empty not allowed)
            payload = {'.id': user_id, 'mac-address': '00:00:00:00:00:00'}

            # Use raw call() instead of .set() to avoid wrapper encoding bugs
            try:
                users_res.call('set', payload)
            except Exception as e:
                # Retry once if router returns an empty sentence / wrapper parse fails
                if 'Malformed sentence' in str(e) or '!empty' in str(e):
                    users_res.call('set', payload)
                else:
                    raise

            # Kick active sessions
            act_res = api.get_resource('/ip/hotspot/active')
            active_list = act_res.get(user=target) or []
            for a in active_list:
                active_id = a.get('id') or a.get('.id')
                if not active_id:
                    continue
                try:
                    act_res.call('remove', {'.id': active_id})
                except Exception:
                    # fallback to wrapper remove if call() isn't supported by your lib
                    act_res.remove(id=active_id)

            log_activity(current_user.username, 'MAC Reset', f'Reset MAC for voucher: {target}')
            flash(f'Success: {target} Reset', 'success')

        except Exception as e:
            flash(f'MAC Reset failed: {str(e)}', 'danger')

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
@bp.route('/admin/get_profiles/<router_id>')
@login_required
@require_flag('can_generate')
def admin_get_profiles(router_id):
    user_with_router = mongo.db.users.find_one({'routers.id': router_id})
    if not user_with_router:
        return {'profiles': [], 'error': 'Router not found'}, 404

    router = next((r for r in user_with_router.get('routers', []) if r.get('id') == router_id), None)
    if not router:
        return {'profiles': [], 'error': 'Router not found'}, 404

    try:
        conn, api = get_api(router)
        profiles = [p['name'] for p in api.get_resource('/ip/hotspot/user/profile').get()]
        conn.disconnect()
        return {'profiles': profiles}
    except Exception as e:
        return {'profiles': [], 'error': str(e)}, 500


@bp.route('/admin/live_template', methods=['GET', 'POST'])
@login_required
@require_flag('allow_live_template')
def live_template():
    """Voucher template editor (global template stored in settings).

    The UI is app/templates/live_template.html.
    """
    tpl_doc = mongo.db.settings.find_one({'type': 'voucher_template'}) or {'type': 'voucher_template', 'html': ''}

    if request.method == 'POST':
        new_html = request.form.get('template_html', '')
        mongo.db.settings.update_one({'type': 'voucher_template'}, {'$set': {'html': new_html}}, upsert=True)
        flash('Template saved!', 'success')
        return redirect(url_for('admin.live_template'))

    return render_template('live_template.html', template_content=tpl_doc.get('html', ''), selected='default')


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
@require_admin
def add_user():
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '').strip()
    role = request.form.get('role', 'user').strip()
    email = request.form.get('email', '').strip()

    if not username or not password:
        flash('Username & password required', 'danger')
        return redirect(url_for('dashboard.dashboard'))
    if mongo.db.users.find_one({'username': username}):
        flash('Username already exists', 'danger')
        return redirect(url_for('dashboard.dashboard'))

    mongo.db.users.insert_one({
        'username': username,
        'password': generate_password_hash(password),
        'role': role,
        'email': email,
        'routers': [],
        'can_generate': False,
        'allow_reports': False,
        'allow_user_manage': False,
    })
    flash('User created', 'success')
    return redirect(url_for('dashboard.dashboard'))


@bp.route('/admin/delete_user/<id>')
@login_required
@require_admin
def delete_user(id):
    try:
        mongo.db.users.delete_one({'_id': ObjectId(id)})
        flash('User deleted', 'success')
    except Exception as e:
        flash(str(e), 'danger')
    return redirect(url_for('dashboard.dashboard'))


@bp.route('/admin/update_user_permission/<user_id>', methods=['POST'])
@login_required
@require_admin
def update_user_permission(user_id):
    payload = {
        'can_generate': bool(request.form.get('can_generate')),
        'allow_reports': bool(request.form.get('allow_reports')),
        'allow_user_manage': bool(request.form.get('allow_user_manage')),
    }
    mongo.db.users.update_one({'_id': ObjectId(user_id)}, {'$set': payload})
    flash('Permissions updated', 'success')
    return redirect(url_for('dashboard.dashboard'))


@bp.route('/admin/login_as_user/<user_id>')
@login_required
@require_admin
def login_as_user(user_id):
    u = mongo.db.users.find_one({'_id': ObjectId(user_id)})
    if not u:
        flash('User not found', 'danger')
        return redirect(url_for('dashboard.dashboard'))
    login_user(User(u))
    flash('Logged in as user', 'info')
    return redirect(url_for('dashboard.dashboard'))


@bp.route('/admin/add_router_to_user', methods=['POST'])
@login_required
@require_admin
def add_router_to_user():
    user_id = request.form.get('user_id')
    router = {
        'id': request.form.get('r_id') or generate_random_string(8, 'mix'),
        'name': request.form.get('r_name', 'Router'),
        'ip': request.form.get('r_host', ''),
        'api_user': request.form.get('r_user', ''),
        'api_pass_enc': encrypt_text(request.form.get('r_pass', '')),
        'dns_name': request.form.get('dns_name', 'login.net'),
    }
    mongo.db.users.update_one({'_id': ObjectId(user_id)}, {'$push': {'routers': router}})
    flash('Router added', 'success')
    return redirect(url_for('dashboard.dashboard'))


@bp.route('/admin/update_router', methods=['POST'])
@login_required
@require_admin
def update_router():
    user_id = request.form.get('u_id')
    r_id = request.form.get('r_id')
    r_pass = (request.form.get('r_pass') or '').strip()
    fields = {
        'routers.$.name': request.form.get('r_name'),
        'routers.$.ip': request.form.get('r_host'),
        'routers.$.api_user': request.form.get('r_user'),
        'routers.$.dns_name': request.form.get('dns_name', 'login.net'),
    }
    if r_pass:
        fields['routers.$.api_pass_enc'] = encrypt_text(r_pass)
    mongo.db.users.update_one({'_id': ObjectId(user_id), 'routers.id': r_id}, {'$set': fields})
    flash('Router updated', 'success')
    return redirect(url_for('dashboard.dashboard'))


@bp.route('/admin/delete_router/<u_id>/<r_id>')
@login_required
@require_admin
def delete_router(u_id, r_id):
    mongo.db.users.update_one({'_id': ObjectId(u_id)}, {'$pull': {'routers': {'id': r_id}}})
    flash('Router deleted', 'success')
    return redirect(url_for('dashboard.dashboard'))


@bp.route('/admin/quick_user/<router_id>', methods=['GET', 'POST'])
@login_required
def quick_user(router_id):
    user_with_router = mongo.db.users.find_one({'routers.id': router_id})
    router = next((r for r in user_with_router.get('routers', []) if r.get('id') == router_id), None) if user_with_router else None
    if not router:
        flash('Router not found', 'danger')
        return redirect(url_for('dashboard.dashboard'))

    profiles = []
    try:
        conn, api = get_api(router)
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
            conn, api = get_api(router)
            api.get_resource('/ip/hotspot/user').add(name=u_name, password=u_pass, profile=profile, comment=comment)
            conn.disconnect()
            flash('User created on router', 'success')
            return redirect(url_for('admin.hotspot_users', router_id=router_id))
        except Exception as e:
            flash(str(e), 'danger')

    return render_template('quick_user.html', router=router, profiles=profiles)
