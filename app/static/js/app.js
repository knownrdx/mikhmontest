/*
  app/static/js/app.js

  Features:
  1) Flash message auto-hide (Bootstrap alerts or plain .flash-auto)
  2) Dark mode toggle (body.theme-dark) + Bootstrap 5.3 color-mode (data-bs-theme)
  3) Loading spinners for forms/buttons:
     - OTP: form[data-otp-form] + button[data-loading-btn]
     - Reports: form[data-report-form] + button[data-loading-btn]
     - Generic: form[data-loading-form] + button[data-loading-btn]
*/

(function () {
  "use strict";

  // -----------------------------
  // 1) Flash auto-hide
  // -----------------------------
  function setupFlashAutoHide() {
    const alerts = document.querySelectorAll('.flash-auto');
    if (!alerts.length) return;

    alerts.forEach((el) => {
      const closeBtn = el.querySelector('.btn-close, .flash-close');

      const hide = () => {
        if (el.classList.contains('hide')) return;
        el.classList.add('hide');
        const remove = () => el.remove();
        el.addEventListener('transitionend', remove, { once: true });
        setTimeout(remove, 400);
      };

      closeBtn?.addEventListener('click', () => {
        setTimeout(() => {
          if (document.body.contains(el)) hide();
        }, 50);
      });

      setTimeout(hide, 3500);
    });
  }

  // -----------------------------
  // 2) Dark mode
  // -----------------------------
  // Use a single shared key across admin + user dashboards.
  // Backward compatible: we will read older keys if present.
  const THEME_KEY = 'ui_theme';
  const LEGACY_KEYS = ['admin_theme', 'user-theme'];

  function getSavedTheme() {
    const direct = localStorage.getItem(THEME_KEY);
    if (direct) return direct;
    for (const k of LEGACY_KEYS) {
      const v = localStorage.getItem(k);
      if (v) return v;
    }
    return 'light';
  }

  function setSavedTheme(theme) {
    localStorage.setItem(THEME_KEY, theme);
    // keep legacy keys in sync so older pages don't feel "broken"
    for (const k of LEGACY_KEYS) localStorage.setItem(k, theme);
  }

  function setThemeBtnIcon(theme) {
    const btn = document.getElementById('themeBtn');
    if (!btn) return;
    btn.innerHTML = theme === 'dark'
      ? '<i class="fa-solid fa-sun nav-ico"></i> Mode'
      : '<i class="fa-solid fa-moon nav-ico"></i> Mode';
  }

  function applySavedTheme() {
    const saved = getSavedTheme();
    document.body.classList.toggle('theme-dark', saved === 'dark');
    document.documentElement.setAttribute('data-bs-theme', saved === 'dark' ? 'dark' : 'light');
    setThemeBtnIcon(saved);
  }

  // Navbar button uses onclick="toggleTheme()"
  window.toggleTheme = function toggleTheme() {
    const isDark = document.body.classList.toggle('theme-dark');
    const newTheme = isDark ? 'dark' : 'light';
    setSavedTheme(newTheme);
    document.documentElement.setAttribute('data-bs-theme', newTheme);
    setThemeBtnIcon(newTheme);
  };

  // -----------------------------
  // 3) Loading spinners
  // -----------------------------
  function setBtnLoading(btn, isLoading) {
    if (!btn) return;
    btn.classList.toggle('btn-loading', !!isLoading);
  }

  function setupLoadingForms() {
    const forms = document.querySelectorAll('form[data-otp-form], form[data-report-form], form[data-loading-form]');
    forms.forEach((form) => {
      form.addEventListener('submit', () => {
        const btn =
          form.querySelector('[data-loading-btn]') ||
          form.querySelector('button[type="submit"], input[type="submit"]');

        if (btn && btn.tagName === 'BUTTON') setBtnLoading(btn, true);

        const pageLoader = document.getElementById('pageLoader');
        if (pageLoader) pageLoader.removeAttribute('hidden');
      });
    });
  }

  // -----------------------------
  // 4) Voucher idempotency token
  // -----------------------------
  function uuidToken() {
    // Prefer crypto random if available
    if (window.crypto && crypto.randomUUID) return crypto.randomUUID();
    const arr = new Uint8Array(16);
    if (window.crypto) crypto.getRandomValues(arr);
    return Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  function setupVoucherTokens() {
    const forms = document.querySelectorAll('form');
    forms.forEach((form) => {
      const tokenInput = form.querySelector('input[name="token"]');
      if (!tokenInput) return;

      const key = 'gen_token_' + (form.getAttribute('action') || window.location.pathname);
      // Pre-fill token so the user can retry without duplicating.
      const existing = sessionStorage.getItem(key);
      if (existing) tokenInput.value = existing;
      else {
        const t = 'gen_' + uuidToken();
        tokenInput.value = t;
        sessionStorage.setItem(key, t);
      }

      // If a reset button exists, let the user force a new token.
      const resetBtn = form.querySelector('[data-reset-token]');
      resetBtn?.addEventListener('click', (e) => {
        e.preventDefault();
        const t = 'gen_' + uuidToken();
        tokenInput.value = t;
        sessionStorage.setItem(key, t);
      });

      form.addEventListener('submit', () => {
        // Ensure token is persisted for retries.
        if (tokenInput.value) sessionStorage.setItem(key, tokenInput.value);
      });
    });
  }

  // -----------------------------
  // 5) CSRF token for AJAX
  // -----------------------------
  function setupCSRF() {
    // Read CSRF token from meta tag (injected by server)
    const meta = document.querySelector('meta[name="csrf-token"]');
    if (!meta) return;
    const token = meta.getAttribute('content');
    if (!token) return;

    // Monkey-patch fetch to auto-include CSRF token in all non-GET requests
    const _origFetch = window.fetch;
    window.fetch = function(url, opts) {
      opts = opts || {};
      const method = (opts.method || 'GET').toUpperCase();
      if (method !== 'GET' && method !== 'HEAD') {
        opts.headers = opts.headers || {};
        // Support both Headers object and plain object
        if (opts.headers instanceof Headers) {
          if (!opts.headers.has('X-CSRFToken')) {
            opts.headers.set('X-CSRFToken', token);
          }
        } else {
          if (!opts.headers['X-CSRFToken']) {
            opts.headers['X-CSRFToken'] = token;
          }
        }
      }
      return _origFetch.call(this, url, opts);
    };
  }

  document.addEventListener('DOMContentLoaded', () => {
    applySavedTheme();
    setupFlashAutoHide();
    setupLoadingForms();
    setupVoucherTokens();
    setupCSRF();

  });
})();
