/*
  MikroMan UX Toolkit v2
  ======================
  All-in-one user-friendliness features:
  
  1. Confirm dialogs (SweetAlert-style, no dependency)
  2. Keyboard shortcuts
  3. Copy to clipboard
  4. Session timeout warning
  5. Auto-refresh (monitor page)
  6. Notification center (bell icon)
  7. Quick actions (floating FAB)
  8. Onboarding tour (first visit)
*/

(function () {
  "use strict";

  // ============================================
  // 1. CONFIRM DIALOGS (replaces browser confirm)
  // ============================================
  const CONFIRM_CSS = `
  .mm-confirm-overlay{position:fixed;inset:0;background:rgba(0,0,0,.55);backdrop-filter:blur(6px);z-index:11000;display:flex;align-items:center;justify-content:center;padding:16px;animation:mmFadeIn .2s ease}
  .mm-confirm-card{background:var(--surface,#fff);border-radius:16px;max-width:380px;width:100%;padding:24px;box-shadow:0 20px 50px rgba(0,0,0,.3);border:1px solid var(--border,#e2e8f0);animation:mmSlideUp .3s cubic-bezier(.34,1.56,.64,1)}
  [data-bs-theme="dark"] .mm-confirm-card{background:#1e293b;border-color:#334155}
  .mm-confirm-icon{width:52px;height:52px;border-radius:50%;display:flex;align-items:center;justify-content:center;margin:0 auto 14px;font-size:22px}
  .mm-confirm-icon.warn{background:rgba(245,158,11,.12);color:#f59e0b}
  .mm-confirm-icon.danger{background:rgba(239,68,68,.12);color:#ef4444}
  .mm-confirm-icon.info{background:rgba(59,130,246,.12);color:#3b82f6}
  .mm-confirm-title{font-weight:700;font-size:1.05rem;text-align:center;margin-bottom:6px;color:var(--text)}
  .mm-confirm-msg{font-size:.85rem;text-align:center;color:var(--muted,#64748b);margin-bottom:18px;line-height:1.5}
  .mm-confirm-btns{display:flex;gap:10px}
  .mm-confirm-btns button{flex:1;padding:10px;border-radius:10px;font-weight:600;font-size:.88rem;border:none;cursor:pointer;transition:all .2s}
  .mm-btn-cancel{background:var(--border,#e2e8f0);color:var(--text)}
  .mm-btn-cancel:hover{opacity:.8}
  .mm-btn-confirm{color:#fff}
  .mm-btn-confirm.danger{background:#ef4444}
  .mm-btn-confirm.danger:hover{background:#dc2626}
  .mm-btn-confirm.warn{background:#f59e0b}
  .mm-btn-confirm.warn:hover{background:#d97706}
  .mm-btn-confirm.primary{background:var(--accent,#2563eb)}
  .mm-btn-confirm.primary:hover{filter:brightness(.9)}
  @keyframes mmFadeIn{from{opacity:0}to{opacity:1}}
  @keyframes mmSlideUp{from{transform:translateY(20px);opacity:0}to{transform:translateY(0);opacity:1}}
  `;

  function injectCSS(css) {
    const s = document.createElement('style');
    s.textContent = css;
    document.head.appendChild(s);
  }

  function mmConfirm({ title, message, type, confirmText, cancelText }) {
    return new Promise((resolve) => {
      type = type || 'warn';
      const icons = { warn: 'fa-exclamation-triangle', danger: 'fa-trash', info: 'fa-info-circle' };
      const el = document.createElement('div');
      el.className = 'mm-confirm-overlay';
      el.innerHTML = `
        <div class="mm-confirm-card">
          <div class="mm-confirm-icon ${type}"><i class="fa-solid ${icons[type] || icons.warn}"></i></div>
          <div class="mm-confirm-title">${title || 'Are you sure?'}</div>
          <div class="mm-confirm-msg">${message || ''}</div>
          <div class="mm-confirm-btns">
            <button class="mm-btn-cancel">${cancelText || 'Cancel'}</button>
            <button class="mm-btn-confirm ${type}">${confirmText || 'Confirm'}</button>
          </div>
        </div>`;
      document.body.appendChild(el);
      el.querySelector('.mm-btn-cancel').onclick = () => { el.remove(); resolve(false); };
      el.querySelector('.mm-btn-confirm').onclick = () => { el.remove(); resolve(true); };
      el.addEventListener('click', (e) => { if (e.target === el) { el.remove(); resolve(false); } });
      // Focus confirm for keyboard
      setTimeout(() => el.querySelector('.mm-btn-confirm').focus(), 50);
      // Esc to cancel
      const esc = (e) => { if (e.key === 'Escape') { el.remove(); resolve(false); document.removeEventListener('keydown', esc); } };
      document.addEventListener('keydown', esc);
    });
  }

  window.mmConfirm = mmConfirm;

  // Auto-upgrade all confirm() links
  document.addEventListener('click', async (e) => {
    const link = e.target.closest('a[onclick*="confirm("]');
    if (!link) return;
    e.preventDefault();
    e.stopPropagation();
    // Extract message from onclick
    const match = link.getAttribute('onclick').match(/confirm\(['"](.+?)['"]\)/);
    const msg = match ? match[1] : 'Are you sure?';
    const isDanger = msg.toLowerCase().includes('delete') || msg.toLowerCase().includes('remove');
    const ok = await mmConfirm({
      title: isDanger ? 'Delete Confirmation' : 'Confirm Action',
      message: msg,
      type: isDanger ? 'danger' : 'warn',
      confirmText: isDanger ? 'Delete' : 'Yes, proceed',
    });
    if (ok) window.location.href = link.href;
  }, true);

  // ============================================
  // 2. KEYBOARD SHORTCUTS
  // ============================================
  const SHORTCUT_CSS = `
  .mm-shortcut-overlay{position:fixed;inset:0;background:rgba(0,0,0,.6);backdrop-filter:blur(8px);z-index:12000;display:flex;align-items:center;justify-content:center;padding:16px;animation:mmFadeIn .2s ease}
  .mm-shortcut-card{background:var(--surface,#fff);border-radius:16px;max-width:440px;width:100%;padding:24px;box-shadow:0 20px 50px rgba(0,0,0,.3);border:1px solid var(--border)}
  [data-bs-theme="dark"] .mm-shortcut-card{background:#1e293b;border-color:#334155}
  .mm-shortcut-title{font-weight:700;font-size:1.1rem;margin-bottom:16px;display:flex;align-items:center;gap:8px}
  .mm-shortcut-row{display:flex;justify-content:space-between;padding:8px 0;border-bottom:1px solid rgba(0,0,0,.05)}
  [data-bs-theme="dark"] .mm-shortcut-row{border-color:rgba(255,255,255,.06)}
  .mm-shortcut-key{display:inline-flex;gap:4px}
  .mm-shortcut-key kbd{background:var(--border,#e2e8f0);color:var(--text);padding:3px 8px;border-radius:6px;font-size:.78rem;font-weight:600;border:1px solid rgba(0,0,0,.1);min-width:28px;text-align:center}
  .mm-shortcut-label{color:var(--muted);font-size:.85rem}
  `;

  let shortcutOverlay = null;

  function showShortcutHelp() {
    if (shortcutOverlay) { shortcutOverlay.remove(); shortcutOverlay = null; return; }
    const el = document.createElement('div');
    el.className = 'mm-shortcut-overlay';
    el.innerHTML = `
      <div class="mm-shortcut-card">
        <div class="mm-shortcut-title"><i class="fa-solid fa-keyboard text-accent"></i> Keyboard Shortcuts</div>
        <div class="mm-shortcut-row"><span class="mm-shortcut-label">Go to Dashboard</span><span class="mm-shortcut-key"><kbd>Alt</kbd><kbd>H</kbd></span></div>
        <div class="mm-shortcut-row"><span class="mm-shortcut-label">Generate Vouchers</span><span class="mm-shortcut-key"><kbd>Alt</kbd><kbd>V</kbd></span></div>
        <div class="mm-shortcut-row"><span class="mm-shortcut-label">Monitor</span><span class="mm-shortcut-key"><kbd>Alt</kbd><kbd>M</kbd></span></div>
        <div class="mm-shortcut-row"><span class="mm-shortcut-label">Reports</span><span class="mm-shortcut-key"><kbd>Alt</kbd><kbd>R</kbd></span></div>
        <div class="mm-shortcut-row"><span class="mm-shortcut-label">Users</span><span class="mm-shortcut-key"><kbd>Alt</kbd><kbd>U</kbd></span></div>
        <div class="mm-shortcut-row"><span class="mm-shortcut-label">Toggle Dark Mode</span><span class="mm-shortcut-key"><kbd>Alt</kbd><kbd>D</kbd></span></div>
        <div class="mm-shortcut-row"><span class="mm-shortcut-label">Search (on page)</span><span class="mm-shortcut-key"><kbd>/</kbd></span></div>
        <div class="mm-shortcut-row"><span class="mm-shortcut-label">Close / Dismiss</span><span class="mm-shortcut-key"><kbd>Esc</kbd></span></div>
        <div class="mm-shortcut-row"><span class="mm-shortcut-label">Show this help</span><span class="mm-shortcut-key"><kbd>?</kbd></span></div>
        <div class="text-center mt-3"><small class="text-muted">Press Esc or ? to close</small></div>
      </div>`;
    document.body.appendChild(el);
    shortcutOverlay = el;
    el.addEventListener('click', (e) => { if (e.target === el) { el.remove(); shortcutOverlay = null; } });
  }

  document.addEventListener('keydown', (e) => {
    // Don't trigger in inputs/textareas
    const tag = (e.target.tagName || '').toLowerCase();
    if (tag === 'input' || tag === 'textarea' || tag === 'select' || e.target.isContentEditable) return;

    // ? = help
    if (e.key === '?' || (e.key === '/' && e.shiftKey)) { e.preventDefault(); showShortcutHelp(); return; }
    // Esc = close overlays
    if (e.key === 'Escape') { if (shortcutOverlay) { shortcutOverlay.remove(); shortcutOverlay = null; } return; }
    // / = focus search
    if (e.key === '/') { const s = document.getElementById('mainSearch') || document.querySelector('input[type="search"]'); if (s) { e.preventDefault(); s.focus(); } return; }
    // Alt+key shortcuts
    if (!e.altKey) return;
    const navMap = {
      'h': '/dashboard', 'v': null, 'm': null, 'r': null, 'u': null, 'd': null
    };
    // Find nav links by text content
    if (e.key === 'h') { window.location.href = '/dashboard'; return; }
    if (e.key === 'd') { if (window.toggleTheme) window.toggleTheme(); return; }

    // Find links in navbar
    const navLinks = document.querySelectorAll('.navbar .nav-link');
    const linkMap = { 'v': 'voucher', 'm': 'monitor', 'r': 'report', 'u': 'user' };
    const search = linkMap[e.key];
    if (search) {
      for (const l of navLinks) {
        if (l.textContent.toLowerCase().includes(search)) { window.location.href = l.href; return; }
      }
    }
  });

  // ============================================
  // 3. COPY TO CLIPBOARD
  // ============================================
  const COPY_CSS = `
  .mm-copyable{cursor:pointer;position:relative;transition:background .2s;border-radius:4px;padding:0 2px}
  .mm-copyable:hover{background:var(--accent-10,rgba(37,99,235,.1))}
  .mm-copy-toast{position:fixed;bottom:20px;left:50%;transform:translateX(-50%);background:#10b981;color:#fff;padding:8px 18px;border-radius:10px;font-size:.82rem;font-weight:600;z-index:12000;animation:mmSlideUp .3s ease;box-shadow:0 6px 20px rgba(0,0,0,.2)}
  `;

  function copyText(text) {
    navigator.clipboard.writeText(text).then(() => {
      const t = document.createElement('div');
      t.className = 'mm-copy-toast';
      t.innerHTML = '<i class="fa-solid fa-check me-1"></i> Copied!';
      document.body.appendChild(t);
      setTimeout(() => t.remove(), 1500);
    }).catch(() => {});
  }

  window.copyText = copyText;

  // Make elements with data-copy clickable
  document.addEventListener('click', (e) => {
    const el = e.target.closest('[data-copy]');
    if (!el) return;
    const val = el.getAttribute('data-copy') || el.textContent.trim();
    copyText(val);
  });

  // Auto-add copy behavior to code, font-monospace elements in tables
  document.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('td code, td .font-monospace, .mm-copyable').forEach(el => {
      if (!el.hasAttribute('data-copy')) {
        el.setAttribute('data-copy', el.textContent.trim());
        el.classList.add('mm-copyable');
        el.title = 'Click to copy';
      }
    });
  });

  // ============================================
  // 4. SESSION TIMEOUT WARNING
  // ============================================
  const SESSION_CSS = `
  .mm-session-bar{position:fixed;top:0;left:0;right:0;z-index:13000;background:linear-gradient(90deg,#f59e0b,#ef4444);color:#fff;text-align:center;padding:8px 16px;font-size:.82rem;font-weight:600;transform:translateY(-100%);transition:transform .4s ease;display:flex;align-items:center;justify-content:center;gap:12px}
  .mm-session-bar.show{transform:translateY(0)}
  .mm-session-bar button{background:rgba(255,255,255,.2);border:1px solid rgba(255,255,255,.4);color:#fff;padding:4px 14px;border-radius:8px;font-size:.78rem;font-weight:600;cursor:pointer;transition:background .2s}
  .mm-session-bar button:hover{background:rgba(255,255,255,.35)}
  `;

  function initSessionWarning() {
    // Session lifetime = 60 min (from Flask config)
    const SESSION_MINUTES = 60;
    const WARN_BEFORE_MIN = 5;
    const sessionStart = Date.now();
    const warnAt = (SESSION_MINUTES - WARN_BEFORE_MIN) * 60 * 1000;

    const bar = document.createElement('div');
    bar.className = 'mm-session-bar';
    bar.innerHTML = `
      <i class="fa-solid fa-clock"></i>
      <span>Session expires in <strong id="mmSessionTimer">${WARN_BEFORE_MIN}:00</strong></span>
      <button onclick="window.location.reload()"><i class="fa-solid fa-rotate-right me-1"></i>Extend</button>
    `;
    document.body.appendChild(bar);

    let warningShown = false;
    setInterval(() => {
      const elapsed = Date.now() - sessionStart;
      const remaining = (SESSION_MINUTES * 60 * 1000) - elapsed;
      if (remaining <= WARN_BEFORE_MIN * 60 * 1000 && remaining > 0 && !warningShown) {
        bar.classList.add('show');
        warningShown = true;
      }
      if (warningShown && remaining > 0) {
        const min = Math.floor(remaining / 60000);
        const sec = Math.floor((remaining % 60000) / 1000);
        const timerEl = document.getElementById('mmSessionTimer');
        if (timerEl) timerEl.textContent = `${min}:${sec.toString().padStart(2, '0')}`;
      }
      if (remaining <= 0) {
        bar.innerHTML = '<i class="fa-solid fa-exclamation-triangle"></i> Session expired. <a href="/login" style="color:#fff;text-decoration:underline;margin-left:8px;">Login again</a>';
      }
    }, 1000);
  }

  // ============================================
  // 5. AUTO-REFRESH (Monitor page)
  // ============================================
  const AUTOREFRESH_CSS = `
  .mm-autorefresh{display:inline-flex;align-items:center;gap:8px;padding:4px 12px;border-radius:20px;background:var(--accent-10,rgba(37,99,235,.1));font-size:.78rem;font-weight:600;color:var(--accent,#2563eb)}
  .mm-autorefresh select{border:none;background:transparent;color:var(--accent);font-weight:600;font-size:.78rem;cursor:pointer;outline:none}
  .mm-ar-dot{width:8px;height:8px;border-radius:50%;background:#10b981;animation:mmPulse 1.5s infinite}
  @keyframes mmPulse{0%,100%{opacity:1}50%{opacity:.3}}
  `;

  function initAutoRefresh() {
    const monitorPage = document.querySelector('.live-indicator');
    if (!monitorPage) return;

    // Find the refresh button area
    const refreshBtn = document.querySelector('button[onclick*="location.reload"]');
    if (!refreshBtn) return;

    const wrap = document.createElement('div');
    wrap.className = 'mm-autorefresh ms-2';
    wrap.innerHTML = `
      <span class="mm-ar-dot"></span>
      Auto:
      <select id="mmAutoRefreshInterval">
        <option value="0">Off</option>
        <option value="5">5s</option>
        <option value="10" selected>10s</option>
        <option value="30">30s</option>
        <option value="60">60s</option>
      </select>
    `;
    refreshBtn.parentNode.insertBefore(wrap, refreshBtn.nextSibling);

    let timer = null;
    const sel = document.getElementById('mmAutoRefreshInterval');
    const saved = localStorage.getItem('mm_autorefresh') || '0';
    sel.value = saved;

    function start() {
      if (timer) clearInterval(timer);
      const val = parseInt(sel.value);
      localStorage.setItem('mm_autorefresh', sel.value);
      if (val > 0) {
        timer = setInterval(() => location.reload(), val * 1000);
        wrap.querySelector('.mm-ar-dot').style.background = '#10b981';
      } else {
        wrap.querySelector('.mm-ar-dot').style.background = '#94a3b8';
      }
    }

    sel.addEventListener('change', start);
    start();
  }

  // ============================================
  // 6. NOTIFICATION CENTER (bell icon in navbar)
  // ============================================
  const NOTIF_CSS = `
  .mm-notif-bell{position:relative;cursor:pointer}
  .mm-notif-badge{position:absolute;top:-4px;right:-4px;background:#ef4444;color:#fff;font-size:.6rem;font-weight:700;width:16px;height:16px;border-radius:50%;display:flex;align-items:center;justify-content:center;animation:mmPulse 2s infinite}
  .mm-notif-dropdown{position:absolute;top:100%;right:0;width:320px;max-height:360px;overflow-y:auto;background:var(--surface,#fff);border:1px solid var(--border);border-radius:14px;box-shadow:0 12px 40px rgba(0,0,0,.2);z-index:5000;display:none;padding:8px 0}
  .mm-notif-dropdown.show{display:block;animation:mmSlideUp .2s ease}
  [data-bs-theme="dark"] .mm-notif-dropdown{background:#1e293b;border-color:#334155}
  .mm-notif-item{padding:10px 14px;border-bottom:1px solid rgba(0,0,0,.04);display:flex;gap:10px;align-items:flex-start;font-size:.82rem;cursor:default;transition:background .15s}
  .mm-notif-item:hover{background:rgba(0,0,0,.02)}
  [data-bs-theme="dark"] .mm-notif-item:hover{background:rgba(255,255,255,.03)}
  .mm-notif-icon{width:32px;height:32px;border-radius:8px;display:flex;align-items:center;justify-content:center;flex-shrink:0;font-size:13px}
  .mm-notif-icon.green{background:rgba(16,185,129,.12);color:#10b981}
  .mm-notif-icon.blue{background:rgba(59,130,246,.12);color:#3b82f6}
  .mm-notif-icon.amber{background:rgba(245,158,11,.12);color:#f59e0b}
  .mm-notif-icon.red{background:rgba(239,68,68,.12);color:#ef4444}
  .mm-notif-text{flex:1;line-height:1.4}
  .mm-notif-time{font-size:.7rem;color:var(--muted);margin-top:2px}
  .mm-notif-empty{text-align:center;padding:24px;color:var(--muted);font-size:.85rem}
  .mm-notif-header{padding:8px 14px;font-weight:700;font-size:.88rem;display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid var(--border)}
  .mm-notif-clear{font-size:.72rem;color:var(--accent);cursor:pointer;font-weight:600}
  `;

  function initNotificationCenter() {
    const navbar = document.querySelector('.navbar .d-flex.flex-column, .navbar .d-flex.gap-2');
    if (!navbar) return;

    const bell = document.createElement('div');
    bell.className = 'mm-notif-bell btn btn-sm btn-outline-secondary rounded-pill px-3';
    bell.innerHTML = `<i class="fa-solid fa-bell nav-ico"></i><span class="mm-notif-badge" id="mmNotifBadge" style="display:none">0</span>`;
    
    const dropdown = document.createElement('div');
    dropdown.className = 'mm-notif-dropdown';
    dropdown.id = 'mmNotifDropdown';
    dropdown.innerHTML = `
      <div class="mm-notif-header">
        <span><i class="fa-solid fa-bell me-1"></i> Notifications</span>
        <span class="mm-notif-clear" id="mmNotifClear">Clear all</span>
      </div>
      <div id="mmNotifList">
        <div class="mm-notif-empty"><i class="fa-solid fa-check-circle me-1"></i> All caught up!</div>
      </div>
    `;

    bell.style.position = 'relative';
    bell.appendChild(dropdown);
    navbar.insertBefore(bell, navbar.firstChild);

    bell.addEventListener('click', (e) => {
      if (e.target.closest('.mm-notif-dropdown')) return;
      dropdown.classList.toggle('show');
    });

    document.addEventListener('click', (e) => {
      if (!e.target.closest('.mm-notif-bell')) dropdown.classList.remove('show');
    });

    // Notification API
    window.mmNotify = function(icon, color, text) {
      const list = document.getElementById('mmNotifList');
      const badge = document.getElementById('mmNotifBadge');
      const empty = list.querySelector('.mm-notif-empty');
      if (empty) empty.remove();
      
      const count = parseInt(badge.textContent || '0') + 1;
      badge.textContent = count;
      badge.style.display = 'flex';

      const item = document.createElement('div');
      item.className = 'mm-notif-item';
      item.innerHTML = `
        <div class="mm-notif-icon ${color}"><i class="fa-solid ${icon}"></i></div>
        <div class="mm-notif-text">${text}<div class="mm-notif-time">Just now</div></div>
      `;
      list.insertBefore(item, list.firstChild);
    };

    document.getElementById('mmNotifClear').addEventListener('click', () => {
      const list = document.getElementById('mmNotifList');
      list.innerHTML = '<div class="mm-notif-empty"><i class="fa-solid fa-check-circle me-1"></i> All caught up!</div>';
      document.getElementById('mmNotifBadge').style.display = 'none';
    });
  }

  // ============================================
  // 7. ONBOARDING TOUR (first visit)
  // ============================================
  const TOUR_CSS = `
  .mm-tour-overlay{position:fixed;inset:0;z-index:14000;pointer-events:none}
  .mm-tour-backdrop{position:fixed;inset:0;background:rgba(0,0,0,.55);z-index:14001;pointer-events:all}
  .mm-tour-highlight{position:absolute;z-index:14002;border-radius:8px;box-shadow:0 0 0 4px var(--accent,#2563eb),0 0 0 9999px rgba(0,0,0,.5);pointer-events:none;transition:all .4s ease}
  .mm-tour-tooltip{position:absolute;z-index:14003;background:var(--surface,#fff);border:1px solid var(--border);border-radius:14px;padding:18px;max-width:320px;box-shadow:0 12px 40px rgba(0,0,0,.25);pointer-events:all;animation:mmSlideUp .3s ease}
  [data-bs-theme="dark"] .mm-tour-tooltip{background:#1e293b;border-color:#334155}
  .mm-tour-step{font-size:.72rem;color:var(--accent);font-weight:700;text-transform:uppercase;letter-spacing:.03em;margin-bottom:4px}
  .mm-tour-title{font-weight:700;font-size:1rem;margin-bottom:6px}
  .mm-tour-desc{font-size:.84rem;color:var(--muted);line-height:1.5;margin-bottom:14px}
  .mm-tour-btns{display:flex;gap:8px;justify-content:flex-end}
  .mm-tour-btns button{padding:7px 16px;border-radius:8px;font-size:.82rem;font-weight:600;border:none;cursor:pointer;transition:all .2s}
  .mm-tour-skip{background:transparent;color:var(--muted)}
  .mm-tour-next{background:var(--accent,#2563eb);color:#fff}
  .mm-tour-next:hover{filter:brightness(.9)}
  .mm-tour-dots{display:flex;gap:5px;justify-content:center;margin-top:10px}
  .mm-tour-dot{width:6px;height:6px;border-radius:50%;background:var(--border)}
  .mm-tour-dot.active{background:var(--accent);width:18px;border-radius:3px}
  `;

  function startTour(steps) {
    let current = 0;
    const overlay = document.createElement('div');
    overlay.className = 'mm-tour-overlay';
    const backdrop = document.createElement('div');
    backdrop.className = 'mm-tour-backdrop';
    const highlight = document.createElement('div');
    highlight.className = 'mm-tour-highlight';
    const tooltip = document.createElement('div');
    tooltip.className = 'mm-tour-tooltip';
    
    overlay.appendChild(backdrop);
    overlay.appendChild(highlight);
    overlay.appendChild(tooltip);
    document.body.appendChild(overlay);

    function showStep(i) {
      const step = steps[i];
      const target = document.querySelector(step.target);
      
      if (target) {
        const rect = target.getBoundingClientRect();
        highlight.style.top = (rect.top + window.scrollY - 4) + 'px';
        highlight.style.left = (rect.left - 4) + 'px';
        highlight.style.width = (rect.width + 8) + 'px';
        highlight.style.height = (rect.height + 8) + 'px';
        highlight.style.display = 'block';
        
        tooltip.style.top = (rect.bottom + window.scrollY + 12) + 'px';
        tooltip.style.left = Math.max(12, Math.min(rect.left, window.innerWidth - 340)) + 'px';
        target.scrollIntoView({ behavior: 'smooth', block: 'center' });
      } else {
        highlight.style.display = 'none';
        tooltip.style.top = '50%';
        tooltip.style.left = '50%';
        tooltip.style.transform = 'translate(-50%, -50%)';
      }

      const dots = steps.map((_, j) => `<div class="mm-tour-dot ${j === i ? 'active' : ''}"></div>`).join('');
      tooltip.innerHTML = `
        <div class="mm-tour-step">Step ${i + 1} of ${steps.length}</div>
        <div class="mm-tour-title">${step.title}</div>
        <div class="mm-tour-desc">${step.description}</div>
        <div class="mm-tour-btns">
          <button class="mm-tour-skip">${i === steps.length - 1 ? '' : 'Skip'}</button>
          <button class="mm-tour-next">${i === steps.length - 1 ? 'Finish ✨' : 'Next →'}</button>
        </div>
        <div class="mm-tour-dots">${dots}</div>
      `;

      tooltip.querySelector('.mm-tour-skip').onclick = () => { overlay.remove(); localStorage.setItem('mm_tour_done', '1'); };
      tooltip.querySelector('.mm-tour-next').onclick = () => {
        if (i < steps.length - 1) { current++; showStep(current); }
        else { overlay.remove(); localStorage.setItem('mm_tour_done', '1');
          if (window.showToast) window.showToast('success', 'Tour Complete!', 'You\'re all set to use MikroMan');
        }
      };
    }

    backdrop.addEventListener('click', () => { overlay.remove(); localStorage.setItem('mm_tour_done', '1'); });
    showStep(0);
  }

  window.startTour = startTour;

  function initOnboarding() {
    if (localStorage.getItem('mm_tour_done')) return;
    // Only run on dashboard
    if (!window.location.pathname.includes('dashboard') && window.location.pathname !== '/') return;
    
    setTimeout(() => {
      const steps = [];
      const navBrand = document.querySelector('.navbar-brand');
      if (navBrand) steps.push({ target: '.navbar-brand', title: 'Welcome to MikroMan! 👋', description: 'This is your hotspot management dashboard. Let\'s take a quick tour.' });
      
      const voucherLink = document.querySelector('a[href*="voucher"], a[href*="create-voucher"]');
      if (voucherLink) steps.push({ target: 'a[href*="voucher"]', title: 'Generate Vouchers', description: 'Click here to create hotspot vouchers. Choose profile, quantity, and get a PDF instantly.' });
      
      const reportLink = document.querySelector('a[href*="report"]');
      if (reportLink) steps.push({ target: 'a[href*="report"]', title: 'Sales Reports', description: 'View your daily and monthly revenue, voucher sales statistics and charts.' });
      
      const monitorLink = document.querySelector('a[href*="monitor"]');
      if (monitorLink) steps.push({ target: 'a[href*="monitor"]', title: 'Live Monitor', description: 'See who\'s connected right now, their IP, MAC, uptime — and kick users if needed.' });

      const themeBtn = document.getElementById('themeBtn');
      if (themeBtn) steps.push({ target: '#themeBtn', title: 'Dark Mode', description: 'Toggle between light and dark themes. Your preference is saved automatically.' });

      if (steps.length >= 2) startTour(steps);
    }, 1500);
  }

  // ============================================
  // INIT ALL
  // ============================================
  injectCSS(CONFIRM_CSS + SHORTCUT_CSS + COPY_CSS + SESSION_CSS + AUTOREFRESH_CSS + NOTIF_CSS + TOUR_CSS);

  document.addEventListener('DOMContentLoaded', () => {
    if (document.querySelector('.navbar')) {
      initSessionWarning();
      initNotificationCenter();
    }
    initAutoRefresh();
    initOnboarding();
  });

})();
