"""
Plan definitions for MikroMan subscription system.

Each plan maps features listed on the landing page to permission flags.
Admin can change plan names/prices in Site Editor, but permission mappings are here.
"""

PLANS = {
    'free': {
        'label': 'Starter (Free)',
        'max_routers': 1,
        'trial_days': 7,           # 0 = no trial, unlimited
        'router_editable': False,  # Can't edit router after saving
        'permissions': {
            'can_generate': True,
            'allow_reports': True,
            'allow_user_manage': True,
            'allow_profiles': False,
            'allow_profile_edit': False,
            'allow_quick_user': False,
            'allow_mac_reset': True,
            'allow_live_template': False,
            'allow_router_manage': False,
            'allow_export_pdf': False,
            'allow_monitor': False,
        },
    },
    'pro': {
        'label': 'Professional',
        'max_routers': 0,          # 0 = unlimited
        'trial_days': 0,
        'router_editable': True,
        'permissions': {
            'can_generate': True,
            'allow_reports': True,
            'allow_user_manage': True,
            'allow_profiles': True,
            'allow_profile_edit': True,
            'allow_quick_user': True,
            'allow_mac_reset': True,
            'allow_live_template': True,
            'allow_router_manage': True,
            'allow_export_pdf': True,
            'allow_monitor': True,
        },
    },
    'enterprise': {
        'label': 'Enterprise',
        'max_routers': 0,
        'trial_days': 0,
        'router_editable': True,
        'permissions': {
            'can_generate': True,
            'allow_reports': True,
            'allow_user_manage': True,
            'allow_profiles': True,
            'allow_profile_edit': True,
            'allow_quick_user': True,
            'allow_mac_reset': True,
            'allow_live_template': True,
            'allow_router_manage': True,
            'allow_export_pdf': True,
            'allow_monitor': True,
        },
    },
    'custom': {
        'label': 'Custom',
        'max_routers': 0,          # unlimited — admin decides
        'trial_days': 0,
        'router_editable': True,
        'permissions': None,       # None = don't auto-set, admin sets manually
    },
}


def get_plan(name):
    """Get plan config by name, fallback to free."""
    return PLANS.get(name, PLANS['free'])


def apply_plan_permissions(user_id, plan_name, mongo_db):
    """Set all permission flags on a user according to their plan."""
    plan = get_plan(plan_name)
    if plan['permissions'] is None:
        # Custom plan: don't auto-set permissions, admin manages manually
        mongo_db.users.update_one({'_id': user_id}, {'$set': {'plan': plan_name}})
        return {'plan': plan_name}
    perms = dict(plan['permissions'])
    perms['plan'] = plan_name
    mongo_db.users.update_one({'_id': user_id}, {'$set': perms})
    return perms


def is_trial_expired(user_doc):
    """Check if a free trial user's trial has expired."""
    from datetime import datetime, timezone
    plan = user_doc.get('plan', 'free')
    if plan != 'free':
        return False
    plan_cfg = get_plan(plan)
    if plan_cfg['trial_days'] <= 0:
        return False
    expires = user_doc.get('plan_expires', '')
    if not expires:
        return False
    try:
        exp_dt = datetime.fromisoformat(expires)
        if exp_dt.tzinfo is None:
            exp_dt = exp_dt.replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc) > exp_dt
    except Exception:
        return False
