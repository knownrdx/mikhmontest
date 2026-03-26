"""
Site blueprint — login redirect, sitemap, robots, custom pages.
"""

from flask import (
    Blueprint, render_template, request, redirect,
    url_for, abort, Response, current_app,
)
from ..extensions import mongo, csrf as _csrf

bp = Blueprint('site', __name__, template_folder='../templates/site')


def _get_site_settings():
    return mongo.db.settings.find_one({'_id': 'site_content'}) or {}


def _get_seo_settings():
    return mongo.db.settings.find_one({'_id': 'seo_settings'}) or {}


def _get_base_url(site=None):
    """Return canonical base URL from settings or auto-detect."""
    if site is None:
        site = _get_site_settings()
    base = (site.get('canonical_base') or '').strip()
    if not base:
        seo = _get_seo_settings()
        base = (seo.get('canonical_base') or '').strip()
    if not base:
        base = request.host_url.rstrip('/')
    return base.rstrip('/')


def _get_page_seo(site, page_key):
    """Get per-page SEO overrides, falling back to global settings."""
    page_seo = site.get('page_seo', {})
    if isinstance(page_seo, dict):
        return page_seo.get(page_key, {})
    return {}


# ─── sitemap.xml (public) ─────────────────────────────────────
@bp.route('/sitemap.xml')
def sitemap_xml():
    doc = mongo.db.settings.find_one({'_id': 'sitemap_cache'})
    if doc and doc.get('xml'):
        return Response(doc['xml'], mimetype='application/xml')
    site = _get_site_settings()
    base = _get_base_url(site)
    xml = f'''<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>{base}/</loc><priority>1.0</priority></url>
</urlset>'''
    return Response(xml, mimetype='application/xml')


# ─── robots.txt (public) ──────────────────────────────────────
@bp.route('/robots.txt')
def robots_txt():
    site = _get_site_settings()
    seo = _get_seo_settings()
    txt = site.get('robots_txt') or seo.get('robots_txt', 'User-agent: *\nAllow: /')
    base = _get_base_url(site)
    txt = txt.replace('{SITE_URL}', base)
    return Response(txt, mimetype='text/plain')


# ─── Custom page ─────────────────────────────────────────────
@bp.route('/p/<slug>')
def custom_page(slug):
    doc = mongo.db.settings.find_one({'_id': 'custom_pages'}) or {}
    page = next((p for p in doc.get('pages', []) if p['slug'] == slug), None)
    if not page:
        abort(404)
    s = _get_site_settings()
    base = _get_base_url(s)
    pseo = _get_page_seo(s, f'cp_{slug}')
    return render_template('site/custom_page.html', page=page, s=s, base_url=base, pseo=pseo)


# ─── Root: always redirect to login ──────────────────────────
@bp.route('/')
def home():
    return redirect(url_for('site.login_redirect'))


# ─── Login redirect ──────────────────────────────────────────
@bp.route('/login')
def login_redirect():
    main_domain = current_app.config.get('MAIN_DOMAIN', '')
    if main_domain:
        scheme = 'https' if request.is_secure else 'http'
        return redirect(f'{scheme}://{main_domain}/auth/login')
    return redirect(url_for('auth.login'))


# CSRF exemptions
_csrf.exempt(sitemap_xml)
_csrf.exempt(robots_txt)
