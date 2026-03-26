from flask_login import UserMixin

class User(UserMixin):
    def __init__(self, d: dict):
        self.id = str(d.get('_id'))
        self.username = d.get('username','')
        self.password = d.get('password','')
        self.role = d.get('role','user')
        self.email = d.get('email','')
        self.created_by = d.get('created_by')
        self.created_at = d.get('created_at')
        # Permission flags (keep in sync with DB fields)
        self.can_generate = bool(d.get('can_generate', False))
        self.allow_reports = bool(d.get('allow_reports', False))
        self.allow_user_manage = bool(d.get('allow_user_manage', False))
        self.allow_profiles = bool(d.get('allow_profiles', False))
        self.allow_profile_edit = bool(d.get('allow_profile_edit', False))
        self.allow_quick_user = bool(d.get('allow_quick_user', False))
        self.allow_mac_reset = bool(d.get('allow_mac_reset', False))
        self.allow_live_template = bool(d.get('allow_live_template', False))
        self.allow_router_manage = bool(d.get('allow_router_manage', False))
        self.allow_export_pdf = bool(d.get('allow_export_pdf', False))
        self.allow_monitor = bool(d.get('allow_monitor', False))
        self.allow_port_lock = bool(d.get('allow_port_lock', False))

        self.routers = d.get('routers', [])

        # UI preferences (navbar/sidebar visibility + landing page)
        self.ui_navbar = bool(d.get('ui_navbar', True))
        self.ui_sidebar = bool(d.get('ui_sidebar', True))
        self.ui_landing = d.get('ui_landing', 'dashboard')
        self.ui_onboarded = bool(d.get('ui_onboarded', False))
