/*
  Toast notification system
  Usage:
    showToast('success', 'Done!', 'Voucher generated successfully');
    showToast('danger', 'Error', 'Connection failed');
    showToast('warning', 'Warning', 'Router offline');
    showToast('info', 'Info', 'OTP sent to email');
*/

(function () {
  "use strict";

  const ICONS = {
    success: 'fa-solid fa-check',
    danger: 'fa-solid fa-xmark',
    error: 'fa-solid fa-xmark',
    warning: 'fa-solid fa-exclamation',
    info: 'fa-solid fa-info',
  };

  const TITLES = {
    success: 'Success',
    danger: 'Error',
    error: 'Error',
    warning: 'Warning',
    info: 'Info',
  };

  let container = null;

  function ensureContainer() {
    if (container && document.body.contains(container)) return container;
    container = document.createElement('div');
    container.className = 'toast-container';
    document.body.appendChild(container);
    return container;
  }

  function showToast(type, title, message, duration) {
    type = type || 'info';
    duration = duration || (type === 'danger' || type === 'error' ? 6000 : 4000);

    const c = ensureContainer();
    const el = document.createElement('div');
    el.className = `toast-item ${type}`;
    el.style.setProperty('--toast-duration', duration + 'ms');

    const iconClass = ICONS[type] || ICONS.info;
    const displayTitle = title || TITLES[type] || 'Notice';

    el.innerHTML = `
      <div class="toast-icon"><i class="${iconClass}"></i></div>
      <div class="toast-content">
        <div class="toast-title">${displayTitle}</div>
        ${message ? `<div class="toast-message">${message}</div>` : ''}
      </div>
      <button class="toast-close" aria-label="Close">&times;</button>
      <div class="toast-timer"></div>
    `;

    const close = el.querySelector('.toast-close');
    const dismiss = () => {
      if (el.classList.contains('hiding')) return;
      el.classList.add('hiding');
      setTimeout(() => el.remove(), 350);
    };

    close.addEventListener('click', dismiss);
    setTimeout(dismiss, duration);

    c.appendChild(el);

    // Max 5 toasts visible
    while (c.children.length > 5) {
      c.children[0].classList.add('hiding');
      setTimeout(() => { if (c.children[0]) c.children[0].remove(); }, 350);
    }
  }

  // Expose globally
  window.showToast = showToast;

  // Auto-convert existing Flask flash messages to toasts on DOMContentLoaded
  document.addEventListener('DOMContentLoaded', () => {
    const flashStack = document.querySelector('.flash-stack');
    if (!flashStack) return;

    const alerts = flashStack.querySelectorAll('.alert');
    alerts.forEach((alert, i) => {
      let type = 'info';
      if (alert.classList.contains('alert-success')) type = 'success';
      else if (alert.classList.contains('alert-danger')) type = 'danger';
      else if (alert.classList.contains('alert-warning')) type = 'warning';
      else if (alert.classList.contains('alert-info')) type = 'info';

      const text = alert.textContent.trim().replace(/×$/, '').trim();
      setTimeout(() => showToast(type, null, text), i * 150);
    });

    // Hide original flash stack
    flashStack.style.display = 'none';
  });
})();
