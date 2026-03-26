import os
from bson.objectid import ObjectId
from flask import Flask, request, redirect, url_for, render_template, session

from .config import get_config
from .extensions import mongo, login_manager, mail, csrf, limiter
from .models.user import User

def create_app():
    app = Flask(__name__, template_folder='templates', static_folder='static')

    # ---- Config (dev/prod) ----
    app.config.from_object(get_config())

    # Init Mongo — Atlas only, DB name parsed from URI
    from urllib.parse import urlparse
    from pymongo import MongoClient

    uri = app.config.get('MONGO_URI')
    if not uri:
        raise RuntimeError('MONGO_URI environment variable is required. Set your MongoDB Atlas connection string.')

    parsed = urlparse(uri)
    db_name = (parsed.path.lstrip('/').split('?')[0]) or 'mikro_system'

    client = MongoClient(uri)
    mongo.cx = client
    mongo.db = client[db_name]

    # ---- DB indexes (token TTL cleanup, uniqueness) ----
    try:
        with app.app_context():
            # PDF cache TTL: 1 minute (old files auto-deleted by MongoDB)
            ttl_seconds = int(os.getenv('GEN_TOKEN_TTL_SECONDS', '60'))
            # Drop old index if TTL changed, then recreate
            try:
                mongo.db.gen_results.drop_index('created_at_1')
            except Exception:
                pass
            mongo.db.gen_results.create_index('created_at', expireAfterSeconds=ttl_seconds)
            mongo.db.gen_results.create_index([('token', 1), ('user_id', 1)], unique=True)

            # Progress docs: auto-expire after 5 minutes
            try:
                mongo.db.gen_progress.drop_index('updated_at_1')
            except Exception:
                pass
            mongo.db.gen_progress.create_index('updated_at', expireAfterSeconds=300)

            # Basic uniqueness (safe for public release)
            mongo.db.users.create_index('username', unique=True)
    except Exception:
        # Index creation failure should not crash the app
        pass

    # Init remaining extensions
    mail.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)

    # Login
    login_manager.login_view = 'auth.login'

    # Ensure PERMANENT_SESSION_LIFETIME is enforced
    @app.before_request
    def _make_session_permanent():
        session.permanent = True

    @login_manager.user_loader
    def load_user(user_id):
        try:
            u = mongo.db.users.find_one({'_id': ObjectId(user_id)})
            return User(u) if u else None
        except Exception:
            return None

    # ---- Error pages (production-grade) ----
    @app.errorhandler(404)
    def not_found(e):
        return render_template('errors/404.html'), 404

    @app.errorhandler(500)
    def server_error(e):
        return render_template('errors/500.html'), 500

    @app.before_request
    def ensure_csrf_token():
        """Ensure CSRF token exists in session before any request.
        This prevents 'CSRF session token is missing' errors on first POST."""
        from flask_wtf.csrf import generate_csrf
        generate_csrf()

        # Runtime fix: if accessing via localhost/127.0.0.1 but cookie domain
        # is set to a production domain, cookies won't persist. Force None.
        host = request.host.split(':')[0]  # strip port
        if host in ('localhost', '127.0.0.1', '0.0.0.0'):
            app.config['SESSION_COOKIE_DOMAIN'] = None
            app.config['REMEMBER_COOKIE_DOMAIN'] = None

    @app.after_request
    def add_security_headers(response):
        """Add security headers to every response."""
        # Prevent clickjacking
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        # Prevent MIME sniffing
        response.headers['X-Content-Type-Options'] = 'nosniff'
        # XSS protection (legacy browsers)
        response.headers['X-XSS-Protection'] = '1; mode=block'
        # Referrer policy
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        # Permissions policy
        response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
        # Content Security Policy — allow Bootstrap CDN, FontAwesome CDN, inline styles (needed for Jinja templates)
        csp = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://fonts.googleapis.com; "
            "font-src 'self' https://cdnjs.cloudflare.com https://fonts.gstatic.com; "
            "img-src 'self' data: blob:; "
            "connect-src 'self'; "
            "frame-ancestors 'self';"
        )
        response.headers['Content-Security-Policy'] = csp

        # Auto-inject CSRF token into all HTML form responses.
        # This avoids having to manually add {{ csrf_token() }} to every template.
        if response.content_type and 'text/html' in response.content_type:
            try:
                from flask_wtf.csrf import generate_csrf
                token = generate_csrf()
                data = response.get_data(as_text=True)
                # Inject CSRF meta tag in <head> for AJAX usage
                csrf_meta = f'<meta name="csrf-token" content="{token}">'
                if '<head>' in data and 'csrf-token' not in data:
                    data = data.replace('<head>', f'<head>{csrf_meta}', 1)
                elif '<head ' in data and 'csrf-token' not in data:
                    # handle <head ...> with attributes
                    import re as _re
                    data = _re.sub(r'(<head[^>]*>)', rf'\1{csrf_meta}', data, count=1)
                # Inject hidden CSRF input into all POST forms
                csrf_input = f'<input type="hidden" name="csrf_token" value="{token}">'
                # Replace <form method="POST"> or <form method="post"> etc
                import re as _re
                def _inject_csrf(match):
                    return match.group(0) + csrf_input
                data = _re.sub(
                    r'<form\b[^>]*method=["\'](?:POST|post)["\'][^>]*>',
                    _inject_csrf,
                    data,
                    flags=_re.IGNORECASE
                )
                response.set_data(data)
            except Exception:
                pass  # Never break response over CSRF injection failure

        return response

    # ---- Global template context (permissions + nav helpers) ----
    @app.context_processor
    def inject_global():
        from flask_login import current_user

        # Always available
        ctx = dict(
            BRAND_NAME=app.config.get('BRAND_NAME', 'MikroMan'),
            APP_VERSION=app.config.get('APP_VERSION', '1.2.0'),
            BRAND_ACCENT=app.config.get('BRAND_ACCENT', '#2563eb'),
            current_endpoint=request.endpoint or '',
            ui_navbar=True,
            ui_sidebar=True,
        )

        if not getattr(current_user, 'is_authenticated', False):
            return ctx

        # Load fresh user doc
        try:
            user_doc = mongo.db.users.find_one({'_id': ObjectId(current_user.id)}) or {}
        except Exception:
            user_doc = {}

        routers = user_doc.get('routers', []) or []
        is_admin = (user_doc.get('role') == 'admin')
        is_staff = (user_doc.get('role') == 'sub-admin')

        if is_admin:
            routers = []
            for u in mongo.db.users.find({'routers': {'$exists': True, '$ne': []}}):
                for r in (u.get('routers') or []):
                    if 'owner' not in r:
                        r = dict(r)
                        r['owner'] = u.get('username', '')
                    routers.append(r)
        elif is_staff:
            # Sub-admin: own routers + managed users' routers (for nav switcher)
            seen_ids = set()
            merged = []
            for r in (user_doc.get('routers', []) or []):
                rid_v = r.get('id', '')
                if rid_v and rid_v not in seen_ids:
                    seen_ids.add(rid_v)
                    merged.append(r)
            staff_id_str = str(user_doc.get('_id', ''))
            for u in mongo.db.users.find({'created_by': staff_id_str, 'routers': {'$exists': True, '$ne': []}}):
                for r in (u.get('routers') or []):
                    rid_v = r.get('id', '')
                    if rid_v and rid_v not in seen_ids:
                        seen_ids.add(rid_v)
                        r = dict(r)
                        r.setdefault('owner', u.get('username', ''))
                        merged.append(r)
            routers = merged

        # Router selection priority:
        # 1) Explicit ?router_id= in URL (user just switched)
        # 2) Session router_id (persisted from last switch)
        # 3) First available router (fallback)
        url_rid = request.args.get('router_id')
        sess_rid = session.get('router_id')
        rid = url_rid or sess_rid or (routers[0].get('id') if routers else None)

        # Validate that the selected router_id actually exists in the user's router list
        selected_router = None
        if rid and routers:
            selected_router = next((r for r in routers if r.get('id') == rid), None)
        # If the stored session router_id doesn't match any available router, fall back
        if not selected_router and routers:
            selected_router = routers[0]
            rid = selected_router.get('id')

        # Always persist the active router to session (and sync admin key)
        if rid:
            session['router_id'] = rid
            session['admin_router_id'] = rid

        def _to_bool(v):
            return v is True or v in (1, '1', 'true', 'True', 'yes', 'on', 'ON')

        can_generate = is_admin or _to_bool(user_doc.get('can_generate'))
        can_reports = is_admin or _to_bool(user_doc.get('allow_reports'))
        can_user_manage = is_admin or _to_bool(user_doc.get('allow_user_manage'))
        can_profiles = is_admin or _to_bool(user_doc.get('allow_profiles'))
        can_profile_edit = is_admin or _to_bool(user_doc.get('allow_profile_edit'))
        can_quick_user = is_admin or _to_bool(user_doc.get('allow_quick_user'))
        can_mac_reset = is_admin or _to_bool(user_doc.get('allow_mac_reset'))
        can_live_template = is_admin or _to_bool(user_doc.get('allow_live_template'))
        can_router_manage = is_admin or _to_bool(user_doc.get('allow_router_manage'))
        can_export_pdf = is_admin or _to_bool(user_doc.get('allow_export_pdf'))
        can_create_user = is_admin or _to_bool(user_doc.get('allow_create_user'))
        can_delete_user = is_admin or _to_bool(user_doc.get('allow_delete_user'))
        can_monitor = is_admin or _to_bool(user_doc.get('allow_monitor'))
        can_batch_delete = is_admin or _to_bool(user_doc.get('allow_batch_delete'))
        can_port_lock = is_admin or _to_bool(user_doc.get('allow_port_lock'))

        # Breadcrumbs (simple, endpoint-based)
        label_map = {
            'dashboard.dashboard': 'Dashboard',
            'dashboard.staff_panel': 'Staff',
            'dashboard.user_panel': 'Home',
            'admin.sales_report': 'Reports',
            'admin.monitor_router': 'Monitor',
            'admin.voucher': 'Voucher',
            'admin.admin_config': 'Config',
            'admin.hotspot_users': 'Users',
            'admin.hotspot_profiles': 'Profiles',
            'admin.port_lock_page': 'Port Lock',
        }
        crumbs = []
        ep = request.endpoint or ''
        # Always start with role home
        if is_admin:
            crumbs.append(('Dashboard', url_for('dashboard.dashboard')))
        else:
            crumbs.append(('Home', url_for('dashboard.dashboard')))
        if ep in label_map and label_map[ep] not in ('Dashboard', 'Home'):
            crumbs.append((label_map[ep], None))

        # Traffic interval setting (10-60s, admin-only)
        app_settings_ctx = mongo.db.settings.find_one({'_id': 'app_settings'}) or {}
        traffic_interval = max(10, min(60, int(app_settings_ctx.get('traffic_interval') or 10)))

        ctx.update(dict(
            user_data=user_doc,
            all_routers=routers,
            selected_router=selected_router,
            traffic_interval=traffic_interval,
            is_admin=is_admin,
            is_staff=is_staff,
            can_generate=can_generate,
            can_reports=can_reports,
            can_user_manage=can_user_manage,
            can_profiles=can_profiles,
            _can_profile_edit=can_profile_edit,
            can_quick_user=can_quick_user,
            can_mac_reset=can_mac_reset,
            can_live_template=can_live_template,
            can_router_manage=can_router_manage,
            can_export_pdf=can_export_pdf,
            can_create_user=can_create_user,
            can_delete_user=can_delete_user,
            can_monitor=can_monitor,
            can_batch_delete=can_batch_delete,
            can_port_lock=can_port_lock,
            manage_profiles=is_admin,
            ui_navbar=(_to_bool(user_doc.get('ui_navbar')) if 'ui_navbar' in user_doc else True),
            ui_sidebar=(_to_bool(user_doc.get('ui_sidebar')) if 'ui_sidebar' in user_doc else True),
            breadcrumbs=crumbs,
        ))
        return ctx

    # Blueprints
    from .routes.auth import bp as auth_bp
    from .routes.dashboard import bp as dash_bp
    from .routes.admin import bp as admin_bp
    from .routes.site import bp as site_bp

    # Always register all blueprints on same domain (no Flask SERVER_NAME needed)
    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(dash_bp)
    app.register_blueprint(admin_bp, url_prefix='/a')
    app.register_blueprint(site_bp, url_prefix='/site')

    # ── First-run setup: redirect to /auth/setup if no admin exists ──
    @app.before_request
    def _check_initial_setup():
        """If no admin user in DB, redirect everything to the setup page."""
        from .routes.auth import needs_setup
        # Skip for static files and the setup route itself
        if request.path.startswith('/static') or request.path == '/auth/setup':
            return
        if needs_setup():
            return redirect(url_for('auth.setup'))

    # Host-based routing: redirect based on subdomain in request
    site_domain = app.config.get('SITE_DOMAIN', '')
    main_domain = app.config.get('MAIN_DOMAIN', '')

    @app.before_request
    def _subdomain_router():
        """Route requests based on Host header — no SERVER_NAME needed."""
        if not site_domain or not main_domain:
            return  # single domain mode, skip

        host = (request.host or '').split(':')[0].lower()

        # site_domain → allow /site/*, /auth/*, /static/*; everything else → login
        if host == site_domain:
            path = request.path
            if path.startswith('/site') or path.startswith('/static') or path.startswith('/auth'):
                return
            # Root or anything else → login
            return redirect('/auth/login')

    @app.route('/')
    def index():
        from flask_login import current_user
        from .routes.auth import needs_setup
        if needs_setup():
            return redirect(url_for('auth.setup'))
        if current_user.is_authenticated:
            return redirect(url_for('dashboard.dashboard'))
        return redirect(url_for('auth.login'))

    return app