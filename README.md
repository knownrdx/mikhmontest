# MikroMan — MikroTik Hotspot Manager

A web-based MikroTik hotspot management panel built with Flask + MongoDB Atlas.

**Version:** 1.5.1 | **Port:** 5100

---

## Features

- Hotspot user management (create, delete, batch operations, voucher generation)
- Multi-router support with live router status (CPU, RAM, uptime via SSE)
- Role-based access: Admin / Sub-Admin / User (permission-based)
- 2FA: Email OTP + TOTP (Authenticator app)
- PDF voucher export with customizable templates
- Brute-force protection, CSRF, security headers
- Light / Dark mode

---

## First Run — Admin Setup

On first launch with an empty database, the app automatically redirects to `/auth/setup`. Fill in username, email, and password — this becomes the **Super Admin**. After setup, the page disappears and normal login takes over.

---

## Environment Variables

All configuration is done via Coolify environment variables.

### Required

| Variable | Description |
|---|---|
| `SECRET_KEY` | Random 64-char hex string |
| `MONGO_URI` | MongoDB Atlas connection string (see below) |
| `ROUTER_SECRET_KEY` | Fernet encryption key for router passwords |
| `COOKIE_SECURE` | Set to `1` (Coolify uses HTTPS) |

### Generate Keys

```bash
# SECRET_KEY
python3 -c "import secrets; print(secrets.token_hex(32))"

# ROUTER_SECRET_KEY (Fernet key)
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

### MongoDB Atlas URI

The database name in the URI determines which database is created:

```
MONGO_URI=mongodb+srv://user:pass@cluster.xxxxx.mongodb.net/client_db_name?retryWrites=true&w=majority
```

`client_db_name` will be automatically created on first write.

### Email / SMTP

| Variable | Default | Description |
|---|---|---|
| `MAIL_SERVER` | `smtp.gmail.com` | SMTP server |
| `MAIL_PORT` | `587` | SMTP port |
| `MAIL_USE_TLS` | `true` | Enable TLS |
| `MAIL_USERNAME` | — | Email address |
| `MAIL_PASSWORD` | — | App password |
| `MAIL_DEFAULT_SENDER` | same as USERNAME | From address |

### Branding

| Variable | Default | Description |
|---|---|---|
| `BRAND_NAME` | `MikroMan` | App name in navbar & title |
| `BRAND_ACCENT` | `#2563eb` | Primary accent color |

---

## Coolify Deployment

### Step 1 — Add Resource

1. **Projects** → your project → **+ New Resource**
2. **Application** → **Public Git Repository** (or connect private repo)
3. Build pack: **Dockerfile** (auto-detected)

### Step 2 — MongoDB Atlas

1. Go to [MongoDB Atlas](https://cloud.mongodb.com)
2. Create a cluster (free tier works)
3. **Network Access** → Add your Coolify server IP (or `0.0.0.0/0`)
4. **Database Access** → Create user with `readWrite` role
5. Copy connection string → set as `MONGO_URI` in Coolify env

### Step 3 — Environment Variables

In Coolify → app → **Environment Variables**, add all required variables.

### Step 4 — Port & Domain

- Container exposes port **5100**
- Add your domain in Coolify → app → **Domains**
- SSL handled automatically via Let's Encrypt

### Step 5 — Deploy

Click **Deploy**. Done.

---

## Security Checklist

- [ ] Set a strong random `SECRET_KEY`
- [ ] Set `ROUTER_SECRET_KEY` (Fernet key)
- [ ] Set `COOKIE_SECURE=1`
- [ ] Use Gmail App Password for `MAIL_PASSWORD`
- [ ] Restrict MongoDB Atlas IP allowlist
- [ ] Never commit `.env` to version control

---

## Project Structure

```
mikroman/
├── app/
│   ├── __init__.py          # App factory
│   ├── config.py            # Production config
│   ├── extensions.py        # Flask extensions
│   ├── models/user.py       # User model
│   ├── routes/
│   │   ├── auth.py          # Login, setup, OTP, TOTP
│   │   ├── dashboard.py     # Dashboard, panels
│   │   ├── admin.py         # Hotspot, voucher, reports, monitor
│   │   └── site.py          # Sitemap, robots, custom pages
│   ├── services/            # MikroTik API, OTP, PDF, etc.
│   ├── utils/               # Crypto, permissions, helpers
│   ├── templates/           # Jinja2 HTML
│   └── static/              # CSS, JS, images
├── run.py                   # Entry point (port 5100)
├── Dockerfile               # Docker build
├── .env.example             # Env template
└── requirements.txt
```
