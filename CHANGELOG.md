# MikroMan Changelog

## v1.5.0 — UI Overhaul & Router Status Fix (2026-03-01)

### 🎨 Light & Dark Mode — Complete Fix
- **Instant theme application**: All pages (admin, sub-admin, user) now apply the saved theme immediately via `<script>` in `<head>`, eliminating the white flash on page load (FOUC)
- **user_panel.html** no longer hardcodes `data-bs-theme="dark"` — it now respects the saved theme preference from localStorage
- **`--surface2` CSS variable** added to both light (`#f1f5f9`) and dark (`#162033`) themes — fixes all elements that used the undefined variable with light-only fallback
- **Deep dark mode overrides** in `common.css`: p-cards, stat-cards, router chips, dropdowns, form inputs, modals, offcanvas, income cards, data tables, log filter pills, QA buttons, form check labels, progress bars, and border utilities now all properly adapt to dark mode
- **Dropdown menus** in dark mode: proper dark background, hover states, and active item highlighting
- **Form controls** in dark mode: inputs and selects use proper surface2 background with correct text and placeholder colors
- **Hotspot log footer** uses CSS variables instead of hardcoded `rgba(15,23,42,.5)`

### 🟢🔴 Router Online/Offline Status — Fixed Everywhere
- **Admin panel carousel**: Router cards are now fully theme-aware — text, backgrounds, stats, and board info badges all use CSS variables and adapt to the current theme. Online dots have a gentle pulse animation
- **Admin panel table badges**: User row status dots now show green/red circles with counts immediately as each router is checked (via SSE), not just after all are done
- **Admin panel individual router dots**: The per-router "Checking..." text in the user table is now replaced with green "Online" / red "Offline" as each SSE result arrives
- **SSE error handling improved**: 30-second timeout failsafe added — if SSE stalls, partial results are shown. On error, any accumulated results are displayed instead of showing "unavailable"
- **Staff/Sub-Admin panel**: Now has background SSE router status checking — router cards update CPU, RAM, active users, and uptime in real-time. Previously showed only static data from page load
- **Staff router card live updates**: Selected router's stats grid (CPU/RAM/Active/Uptime) updates dynamically as SSE results arrive, with proper online/offline indicator

### 🔧 General Fixes
- **Skeleton loading in admin panel**: Uses `var(--surface2)` instead of hardcoded light-mode color
- **Carousel dot colors**: Dark mode dots use `rgba(255,255,255,.15)` instead of `rgba(0,0,0,.14)` which was invisible on dark backgrounds
- **All inline style fallbacks** across admin_panel, staff_panel now reference CSS variables instead of hardcoded light-mode hex colors
- **stat-label, stat-sub, stat-value, fl, data-table** elements all use `var(--muted)` and `var(--text)` for proper theming
- **Version bumped** to 1.5.0

## v1.2.1 — Security Hardening (2026-02-20)

### 🔒 Security Fixes

**Router Ownership Enforcement**
- `_get_router_for_current_user()` — new secure resolver; non-admin users can only access their own routers
- `hotspot_users`, `monitor_router`, `kick_user`, `get_traffic` — all now enforce ownership
- Previously, knowing any router_id was enough to access it regardless of who owned it

**Brute Force Protection**
- Login: 5 failed attempts → 15-minute lockout, counter shown per attempt (`3/5 attempts`)
- TOTP: 5 wrong codes → 10-minute lockout, auto-redirect to login
- Lockout state stored in DB (`login_fails`, `lockout_until`, `totp_fails`, `totp_lockout`)
- All counters reset to 0 on successful login

**OTP Expiry**
- Email OTP now expires after 5 minutes (`otp_expiry` stored in DB)
- Expired OTP → clear OTP from DB and redirect to login with message

**Security Headers (all responses)**
- `X-Frame-Options: SAMEORIGIN` — clickjacking protection
- `X-Content-Type-Options: nosniff` — MIME sniffing prevention  
- `X-XSS-Protection: 1; mode=block` — legacy browser XSS
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Content-Security-Policy` — restricts script/style/font/image sources
- `Permissions-Policy` — disables geolocation, microphone, camera

**TOTP Brute Force**
- Wrong TOTP code tracked per user, lockout after 5 attempts

**Password Validation**
- Minimum 6 characters enforced on profile update and admin user creation

**Audit Logging**
- `last_login` (datetime UTC) and `last_login_ip` stored on every successful login
- Unknown username login attempts logged to `security` logger with IP
- Last login shown on Profile page

### 📋 Security Checklist (for production deployment)
- [ ] Set a strong random `SECRET_KEY` in `.env`
- [ ] Set `ROUTER_SECRET_KEY` (Fernet key) in `.env`
- [ ] Set `COOKIE_SECURE=1` if running behind HTTPS
- [ ] Use Gmail App Password (not account password) for `MAIL_PASSWORD`
- [ ] Keep `.env` out of version control (`.gitignore` included)

## v1.2.0 (2026-02-19)

### New Features
- **Admin Users Page** — `/admin/users` — dedicated full-page account list with card grid, search, role/status filter, pagination
- **Sub Admin Panel** — completely redesigned to match Admin layout; sensitive info (IP, API credentials, server data) hidden
- **Voucher Serial System** — each batch gets one shared serial `vc-XXX` instead of per-voucher serials
- **OTP Email** — modern HTML email with digit boxes, brand colors, security notice, plain-text fallback
- **System Status Card** — CPU/RAM/Storage progress bars with color-coded health, board info, platform chips

### Improvements
- **Chart Legend** — removed default Chart.js legend; replaced with inline pill badges (↓ Download / ↑ Upload)
- **Validity Field** — readonly with lock icon; auto-fetched from profile, not manually editable
- **Voucher Gen Overlay** — added Cancel button (while running) and Close button (after done/failed)
- **Select All** — now selects only current page/view; label changes contextually (SELECT COMMENT / SELECT PAGE etc.)
- **Comment Filter** — selecting a comment shows only those users; no forced "available only" side-effect
- **Profile Filter** — no longer forces "available only" mode; shows all matching rows
- **User Add Form** — "Copy Router From Existing User" dropdown; Sub Admin hides router section
- **Buttons (hotspot_users)** — grouped into btn-group, responsive on all screen sizes
- **Monitor Page** — fixed CSS/Jinja syntax error (`animation: spin {{ interval }}s`)

### Bug Fixes
- Permission button hidden in admin/sub-admin panel — now uses reliable `is_admin` flag
- Progress counter `0 / N` frozen during bulk delete — fixed initial call and batch update
- Sub Admin panel `i_created` check blocking Permissions button for all users
- `copy_router_from = "__self__"` handled gracefully in backend
- `Users [1]` count badge removed from hotspot_users header

### Internal
- `APP_VERSION = '1.2.0'` added to config + context processor
- Version shown in sidebar footer
