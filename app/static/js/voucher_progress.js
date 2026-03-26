/*
  Modern Voucher Generation Progress
  - Step indicators (Connect → Generate → PDF → Done)
  - ETA and speed calculation
  - Confetti on success
  - Auto-download
  - TTL countdown for cached PDF (1 minute)
*/

(function () {
  "use strict";

  const DOWNLOAD_TTL_SECONDS = 60; // 1 minute

  const form = document.getElementById('voucherForm');
  if (!form) return;

  // Ensure a token input exists
  let tokenEl = form.querySelector('input[name="token"]');
  if (!tokenEl) {
    tokenEl = document.createElement('input');
    tokenEl.type = 'hidden';
    tokenEl.name = 'token';
    form.appendChild(tokenEl);
  }

  function makeToken() {
    if (window.crypto && crypto.randomUUID) return 'gen_' + crypto.randomUUID();
    const arr = new Uint8Array(16);
    if (window.crypto) crypto.getRandomValues(arr);
    return 'gen_' + Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  // Build overlay HTML
  const overlayHTML = `
  <div id="genOverlay" class="gen-overlay d-none">
    <div class="gen-card" style="position:relative;">
      <div class="gen-confetti" id="genConfetti"></div>
      
      <!-- Header -->
      <div class="gen-header">
        <div class="gen-icon-wrap running" id="genIconWrap">
          <i class="fa-solid fa-bolt" id="genIcon"></i>
        </div>
        <div>
          <p class="gen-title" id="genTitle">Generating Vouchers</p>
          <p class="gen-subtitle" id="genSubtitle">Please don't close this tab</p>
        </div>
      </div>

      <!-- Animated worker character -->
      <div class="gen-worker-wrap" id="genWorkerWrap">
        <svg viewBox="0 0 320 100" class="gen-worker-svg" xmlns="http://www.w3.org/2000/svg">
          <!-- Cable line being drawn -->
          <line x1="0" y1="62" x2="320" y2="62" stroke="var(--border,#cbd5e1)" stroke-width="3" stroke-dasharray="6,4" opacity="0.4"/>
          
          <!-- Active cable (animated draw) -->
          <line class="cable-active" x1="0" y1="62" x2="320" y2="62" stroke="var(--accent,#2563eb)" stroke-width="3" stroke-linecap="round"/>
          
          <!-- Data packets flowing on cable -->
          <g class="data-packets">
            <rect class="pkt pkt1" x="0" y="58" width="12" height="8" rx="3" fill="var(--accent,#2563eb)" opacity="0.8"/>
            <rect class="pkt pkt2" x="0" y="58" width="8" height="8" rx="3" fill="#8b5cf6" opacity="0.7"/>
            <rect class="pkt pkt3" x="0" y="58" width="10" height="8" rx="3" fill="#10b981" opacity="0.7"/>
          </g>
          
          <!-- Router (left side) -->
          <g class="router-box" transform="translate(10,38)">
            <rect width="36" height="28" rx="5" fill="var(--accent,#2563eb)" opacity="0.15" stroke="var(--accent,#2563eb)" stroke-width="1.5"/>
            <rect x="8" y="6" width="4" height="4" rx="1" fill="var(--accent,#2563eb)" class="router-led led1"/>
            <rect x="15" y="6" width="4" height="4" rx="1" fill="#10b981" class="router-led led2"/>
            <rect x="22" y="6" width="4" height="4" rx="1" fill="#f59e0b" class="router-led led3"/>
            <line x1="8" y1="18" x2="28" y2="18" stroke="var(--accent,#2563eb)" stroke-width="1" opacity="0.4"/>
            <line x1="8" y1="22" x2="22" y2="22" stroke="var(--accent,#2563eb)" stroke-width="1" opacity="0.3"/>
          </g>
          
          <!-- Worker person (walking along cable) -->
          <g class="worker-person" transform="translate(140,14)">
            <!-- Hard hat -->
            <ellipse cx="12" cy="6" rx="10" ry="6" fill="#f59e0b"/>
            <rect x="3" y="4" width="18" height="3" rx="1" fill="#f59e0b"/>
            
            <!-- Head -->
            <circle cx="12" cy="14" r="7" fill="#fbbf24" stroke="#d97706" stroke-width="1"/>
            <!-- Eyes -->
            <circle cx="9.5" cy="13" r="1.2" fill="#1e293b"/>
            <circle cx="14.5" cy="13" r="1.2" fill="#1e293b"/>
            <!-- Smile -->
            <path d="M9 16.5 Q12 19 15 16.5" fill="none" stroke="#92400e" stroke-width="0.8" stroke-linecap="round"/>
            
            <!-- Body -->
            <rect x="6" y="21" width="12" height="16" rx="3" fill="#3b82f6"/>
            <!-- Vest -->
            <rect x="7" y="22" width="10" height="6" rx="1" fill="#1d4ed8" opacity="0.6"/>
            <line x1="12" y1="22" x2="12" y2="28" stroke="#93c5fd" stroke-width="0.8"/>
            
            <!-- Left arm (holding cable) -->
            <g class="arm-left">
              <line x1="6" y1="24" x2="-2" y2="34" stroke="#fbbf24" stroke-width="3" stroke-linecap="round"/>
              <!-- Hand holding cable connector -->
              <circle cx="-2" cy="35" r="2.5" fill="#fbbf24"/>
              <!-- RJ45 connector -->
              <rect x="-8" y="32" width="7" height="5" rx="1" fill="#64748b" stroke="#475569" stroke-width="0.5"/>
              <rect x="-7" y="33" width="1" height="3" fill="#94a3b8"/>
              <rect x="-5" y="33" width="1" height="3" fill="#94a3b8"/>
              <rect x="-3" y="33" width="1" height="3" fill="#94a3b8"/>
            </g>
            
            <!-- Right arm -->
            <g class="arm-right">
              <line x1="18" y1="24" x2="26" y2="32" stroke="#fbbf24" stroke-width="3" stroke-linecap="round"/>
              <circle cx="26" cy="33" r="2.5" fill="#fbbf24"/>
            </g>
            
            <!-- Legs (walking) -->
            <g class="legs">
              <line class="leg-l" x1="8" y1="37" x2="5" y2="48" stroke="#1e3a5f" stroke-width="3" stroke-linecap="round"/>
              <line class="leg-r" x1="16" y1="37" x2="19" y2="48" stroke="#1e3a5f" stroke-width="3" stroke-linecap="round"/>
              <!-- Boots -->
              <rect class="boot-l" x="2" y="46" width="7" height="4" rx="2" fill="#475569"/>
              <rect class="boot-r" x="16" y="46" width="7" height="4" rx="2" fill="#475569"/>
            </g>
          </g>
          
          <!-- Voucher stack (right side, being generated) -->
          <g class="voucher-stack" transform="translate(260,32)">
            <rect class="v-card v1" x="0" y="8" width="32" height="22" rx="3" fill="#fff" stroke="var(--border,#e2e8f0)" stroke-width="1"/>
            <rect class="v-card v2" x="3" y="4" width="32" height="22" rx="3" fill="#fff" stroke="var(--border,#e2e8f0)" stroke-width="1"/>
            <rect class="v-card v3" x="6" y="0" width="32" height="22" rx="3" fill="#fff" stroke="var(--accent,#2563eb)" stroke-width="1.5"/>
            <!-- Lines on top card -->
            <line x1="10" y1="5" x2="30" y2="5" stroke="var(--accent,#2563eb)" stroke-width="2" opacity="0.6"/>
            <line x1="10" y1="10" x2="34" y2="10" stroke="#cbd5e1" stroke-width="1.5"/>
            <line x1="10" y1="14" x2="28" y2="14" stroke="#cbd5e1" stroke-width="1.5"/>
            <!-- Checkmark appearing -->
            <circle class="v-check" cx="34" cy="0" r="6" fill="#10b981"/>
            <path class="v-check-mark" d="M31 0 L33 2.5 L37 -2" fill="none" stroke="#fff" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
          </g>
          
          <!-- Sparkles around worker -->
          <g class="sparkles">
            <circle class="spark s1" cx="120" cy="20" r="2" fill="#f59e0b"/>
            <circle class="spark s2" cx="175" cy="10" r="1.5" fill="#3b82f6"/>
            <circle class="spark s3" cx="195" cy="25" r="2" fill="#10b981"/>
            <circle class="spark s4" cx="130" cy="45" r="1.5" fill="#ec4899"/>
          </g>
        </svg>
      </div>

      <!-- Steps -->
      <div class="gen-steps" id="genSteps">
        <div class="gen-step active" data-step="connect">
          <div class="gen-step-dot"><i class="fa-solid fa-plug" style="font-size:9px"></i></div>
          <div class="gen-step-line"></div>
          <span class="gen-step-label">Connect</span>
        </div>
        <div class="gen-step" data-step="generate">
          <div class="gen-step-dot"><i class="fa-solid fa-bolt" style="font-size:9px"></i></div>
          <div class="gen-step-line"></div>
          <span class="gen-step-label">Generate</span>
        </div>
        <div class="gen-step" data-step="pdf">
          <div class="gen-step-dot"><i class="fa-solid fa-file-pdf" style="font-size:9px"></i></div>
          <div class="gen-step-line"></div>
          <span class="gen-step-label">Build PDF</span>
        </div>
        <div class="gen-step" data-step="done">
          <div class="gen-step-dot"><i class="fa-solid fa-check" style="font-size:9px"></i></div>
          <span class="gen-step-label">Done</span>
        </div>
      </div>

      <!-- Progress bar -->
      <div class="gen-progress-track">
        <div class="gen-progress-fill" id="genBar" style="width:0%"></div>
      </div>

      <!-- Stats -->
      <div class="gen-stats">
        <div class="gen-stat-item">
          <span class="gen-stat-value" id="genPct">0%</span>
          <span class="gen-stat-label">Progress</span>
        </div>
        <div class="gen-stat-item">
          <span class="gen-stat-value" id="genSpeed">--</span>
          <span class="gen-stat-label">Speed</span>
        </div>
        <div class="gen-stat-item">
          <span class="gen-stat-value" id="genETA">--</span>
          <span class="gen-stat-label">ETA</span>
        </div>
      </div>

      <!-- Status message -->
      <div class="gen-message" id="genMsg">Connecting to router...</div>

      <!-- Download button (hidden initially) -->
      <a id="genDownloadBtn" class="gen-download-btn d-none" href="#">
        <i class="fa-solid fa-download"></i> Download PDF
      </a>

      <!-- TTL warning (hidden initially) -->
      <div id="genTTL" class="gen-ttl-warning d-none">
        <i class="fa-solid fa-clock"></i> Download expires in <span class="ttl-timer" id="genTTLTimer">60s</span>
      </div>

      <!-- Action buttons row -->
      <div id="genActionRow" style="display:flex;gap:10px;margin-top:14px;">
        <button id="genCancelBtn"
          style="flex:1;padding:9px 0;border-radius:10px;border:1.5px solid rgba(239,68,68,.35);
                 background:rgba(239,68,68,.07);color:#ef4444;font-weight:700;font-size:.85rem;cursor:pointer;">
          <i class="fa-solid fa-ban" style="margin-right:6px;"></i>Cancel
        </button>
        <button id="genCloseBtn"
          style="flex:1;padding:9px 0;border-radius:10px;border:1.5px solid rgba(37,99,235,.3);
                 background:rgba(37,99,235,.08);color:var(--accent,#2563eb);font-weight:700;font-size:.85rem;
                 cursor:pointer;display:none;">
          <i class="fa-solid fa-xmark" style="margin-right:6px;"></i>Close
        </button>
      </div>
    </div>
  </div>`;

  // Insert overlay into page
  const wrapper = document.createElement('div');
  wrapper.innerHTML = overlayHTML;
  document.body.appendChild(wrapper.firstElementChild);

  // Bind Cancel button
  document.getElementById('genCancelBtn').addEventListener('click', function() {
    window._genCancelRequested = true;
    this.disabled = true;
    this.innerHTML = '<i class="fa-solid fa-spinner fa-spin" style="margin-right:6px;"></i>Cancelling...';
  });

  // Bind Close button
  document.getElementById('genCloseBtn').addEventListener('click', function() {
    hideOverlay();
  });

  // References
  const overlay = document.getElementById('genOverlay');
  const bar = document.getElementById('genBar');
  const pctEl = document.getElementById('genPct');
  const speedEl = document.getElementById('genSpeed');
  const etaEl = document.getElementById('genETA');
  const msgEl = document.getElementById('genMsg');
  const titleEl = document.getElementById('genTitle');
  const subtitleEl = document.getElementById('genSubtitle');
  const iconWrap = document.getElementById('genIconWrap');
  const iconEl = document.getElementById('genIcon');
  const downloadBtn = document.getElementById('genDownloadBtn');
  const ttlDiv = document.getElementById('genTTL');
  const ttlTimerEl = document.getElementById('genTTLTimer');
  const confettiEl = document.getElementById('genConfetti');
  const workerWrap = document.getElementById('genWorkerWrap');

  let startTime = 0;
  let lastProgress = 0;
  let totalQty = 0;
  let ttlInterval = null;
  window._genCancelRequested = false;

  function _getCancelBtn() { return document.getElementById('genCancelBtn'); }
  function _getCloseBtn()  { return document.getElementById('genCloseBtn'); }

  function showCancelOnly() {
    const cancel = _getCancelBtn(); const close = _getCloseBtn();
    if (cancel) { cancel.style.display = ''; cancel.disabled = false; cancel.innerHTML = '<i class="fa-solid fa-ban" style="margin-right:6px;"></i>Cancel'; }
    if (close)  close.style.display = 'none';
  }

  function showCloseOnly() {
    const cancel = _getCancelBtn(); const close = _getCloseBtn();
    if (cancel) cancel.style.display = 'none';
    if (close)  close.style.display = '';
  }

  function showBothButtons() {
    const cancel = _getCancelBtn(); const close = _getCloseBtn();
    if (cancel) { cancel.style.display = ''; cancel.disabled = false; cancel.innerHTML = '<i class="fa-solid fa-ban" style="margin-right:6px;"></i>Cancel'; }
    if (close)  close.style.display = '';
  }

  function showOverlay() {
    overlay.classList.remove('d-none');
    document.body.classList.add('overflow-hidden');
  }

  function hideOverlay() {
    overlay.classList.add('d-none');
    document.body.classList.remove('overflow-hidden');
    if (ttlInterval) clearInterval(ttlInterval);
  }

  function setStep(stepName) {
    const steps = document.querySelectorAll('#genSteps .gen-step');
    let found = false;
    steps.forEach(s => {
      if (found) {
        s.classList.remove('active', 'completed');
      } else if (s.dataset.step === stepName) {
        s.classList.add('active');
        s.classList.remove('completed');
        found = true;
      } else {
        s.classList.remove('active');
        s.classList.add('completed');
        // Fill the line
        const line = s.querySelector('.gen-step-line');
        if (line) line.classList.add('filled');
      }
    });
  }

  function setAllStepsCompleted() {
    document.querySelectorAll('#genSteps .gen-step').forEach(s => {
      s.classList.add('completed');
      s.classList.remove('active');
      const line = s.querySelector('.gen-step-line');
      if (line) line.classList.add('filled');
    });
  }

  function resetSteps() {
    document.querySelectorAll('#genSteps .gen-step').forEach((s, i) => {
      s.classList.remove('active', 'completed');
      const line = s.querySelector('.gen-step-line');
      if (line) line.classList.remove('filled');
      if (i === 0) s.classList.add('active');
    });
  }

  function formatETA(seconds) {
    if (!seconds || seconds < 0 || !isFinite(seconds)) return '--';
    if (seconds < 60) return Math.ceil(seconds) + 's';
    const m = Math.floor(seconds / 60);
    const s = Math.ceil(seconds % 60);
    return m + 'm ' + s + 's';
  }

  function updateStats(progress, total) {
    const elapsed = (Date.now() - startTime) / 1000;
    const speed = elapsed > 0 ? (progress / elapsed) : 0;
    const remaining = total - progress;
    const eta = speed > 0 ? remaining / speed : 0;

    speedEl.textContent = speed > 0 ? speed.toFixed(1) + '/s' : '--';
    etaEl.textContent = formatETA(eta);
  }

  function spawnConfetti() {
    const colors = ['#10b981', '#3b82f6', '#f59e0b', '#ec4899', '#8b5cf6', '#ef4444'];
    confettiEl.innerHTML = '';
    for (let i = 0; i < 40; i++) {
      const piece = document.createElement('div');
      piece.className = 'confetti-piece';
      piece.style.left = Math.random() * 100 + '%';
      piece.style.top = Math.random() * 30 + '%';
      piece.style.background = colors[Math.floor(Math.random() * colors.length)];
      piece.style.animationDelay = (Math.random() * 0.5) + 's';
      piece.style.width = (4 + Math.random() * 8) + 'px';
      piece.style.height = (4 + Math.random() * 8) + 'px';
      confettiEl.appendChild(piece);
    }
  }

  function startTTLCountdown(token) {
    let remaining = DOWNLOAD_TTL_SECONDS;
    ttlDiv.classList.remove('d-none');
    ttlTimerEl.textContent = remaining + 's';
    ttlTimerEl.className = 'ttl-timer';

    if (ttlInterval) clearInterval(ttlInterval);
    ttlInterval = setInterval(() => {
      remaining--;
      if (remaining <= 0) {
        clearInterval(ttlInterval);
        ttlTimerEl.textContent = 'EXPIRED';
        ttlTimerEl.className = 'ttl-expired';
        downloadBtn.classList.add('d-none');
        msgEl.textContent = 'Download link expired. Generate again.';
        msgEl.className = 'gen-message failed';
        subtitleEl.textContent = 'The cached PDF has been removed';
        return;
      }
      ttlTimerEl.textContent = remaining + 's';
      if (remaining <= 10) {
        ttlTimerEl.className = 'ttl-expired';
      }
    }, 1000);
  }

  function setDone(token) {
    bar.style.width = '100%';
    bar.classList.add('done');
    pctEl.textContent = '100%';
    etaEl.textContent = '0s';

    setAllStepsCompleted();

    iconWrap.className = 'gen-icon-wrap done';
    iconEl.className = 'fa-solid fa-check';
    titleEl.textContent = 'Generation Complete!';
    subtitleEl.textContent = 'Your vouchers are ready';
    msgEl.textContent = 'PDF ready — downloading automatically...';
    msgEl.className = 'gen-message done';

    // Worker celebrates
    if (workerWrap) {
      workerWrap.classList.remove('failed');
      workerWrap.classList.add('done');
    }

    spawnConfetti();

    // Show download button
    const url = (window.__voucherUrls?.download || '/a/admin/vouchers/download/__TOKEN__').replace('__TOKEN__', token);
    downloadBtn.href = url;
    downloadBtn.classList.remove('d-none');

    // Auto-download
    setTimeout(() => {
      window.location = url;
    }, 600);

    // Start TTL countdown
    startTTLCountdown(token);

    // Show Close, hide Cancel
    showCloseOnly();

    // Toast
    if (window.showToast) {
      window.showToast('success', 'Complete!', `${totalQty} vouchers generated successfully`);
    }
  }

  function setFailed(message) {
    bar.classList.add('failed');
    iconWrap.className = 'gen-icon-wrap failed';
    iconEl.className = 'fa-solid fa-xmark';
    titleEl.textContent = 'Generation Failed';
    subtitleEl.textContent = 'Something went wrong';
    msgEl.textContent = message || 'Unknown error';
    msgEl.className = 'gen-message failed';
    speedEl.textContent = '--';
    etaEl.textContent = '--';

    // Worker sad
    if (workerWrap) {
      workerWrap.classList.remove('done');
      workerWrap.classList.add('failed');
    }

    if (window.showToast) {
      window.showToast('danger', 'Failed', message || 'Voucher generation failed');
    }

    // Show both buttons on failure so user can close immediately
    showBothButtons();
    setTimeout(hideOverlay, 6000);
  }

  async function pollProgress(token) {
    const res = await fetch((window.__voucherUrls?.progress || '/a/admin/vouchers/progress/__TOKEN__').replace('__TOKEN__', token), { credentials: 'same-origin' });
    if (!res.ok) throw new Error('progress request failed');
    return res.json();
  }

  async function startGeneration() {
    // Reset UI
    bar.style.width = '0%';
    bar.classList.remove('done', 'failed');
    pctEl.textContent = '0%';
    speedEl.textContent = '--';
    etaEl.textContent = '--';
    msgEl.textContent = 'Connecting to router...';
    msgEl.className = 'gen-message';
    titleEl.textContent = 'Generating Vouchers';
    subtitleEl.textContent = "Please don't close this tab";
    iconWrap.className = 'gen-icon-wrap running';
    iconEl.className = 'fa-solid fa-bolt';
    downloadBtn.classList.add('d-none');
    ttlDiv.classList.add('d-none');
    confettiEl.innerHTML = '';
    resetSteps();

    // Reset worker character
    if (workerWrap) {
      workerWrap.classList.remove('done', 'failed');
    }

    // Get fresh token
    tokenEl.value = makeToken();
    startTime = Date.now();
    lastProgress = 0;

    try {
      totalQty = parseInt(form.querySelector('[name="qty"]')?.value) || 1;
    } catch (e) {
      totalQty = 1;
    }

    showOverlay();
    window._genCancelRequested = false;
    showCancelOnly();

    const fd = new FormData(form);
    try {
      const startRes = await fetch(window.__voucherUrls?.start || '/a/admin/vouchers/start', { method: 'POST', body: fd, credentials: 'same-origin' });
      const startJson = await startRes.json().catch(() => ({ ok: false, error: 'Unknown error' }));

      if (!startRes.ok || !startJson.ok) {
        setFailed(startJson.error || 'Failed to start');
        return;
      }

      const token = startJson.token;

      if (startJson.status === 'done') {
        setStep('done');
        setDone(token);
        return;
      }

      setStep('generate');

      // Poll loop
      const tick = async () => {
        if (window._genCancelRequested) {
          setFailed('Cancelled by user.');
          return;
        }
        try {
          const p = await pollProgress(token);
          const percent = Math.max(0, Math.min(100, parseInt(p.percent || 0)));

          bar.style.width = percent + '%';
          pctEl.textContent = percent + '%';

          const currentProgress = parseInt(p.progress || 0);
          if (currentProgress > lastProgress) lastProgress = currentProgress;
          updateStats(lastProgress, totalQty);

          // Determine step
          if (percent >= 95) {
            setStep('pdf');
            msgEl.textContent = 'Building PDF document...';
          } else if (percent > 0) {
            setStep('generate');
            msgEl.textContent = p.message || `Generating ${lastProgress}/${totalQty}...`;
          }

          if (p.status === 'done') {
            setDone(token);
            return;
          }

          if (p.status === 'failed') {
            setFailed(p.message || 'Generation failed');
            return;
          }
        } catch (e) {
          msgEl.textContent = 'Connection hiccup… retrying';
        }
        setTimeout(tick, 350);
      };

      setTimeout(tick, 350);
    } catch (e) {
      setFailed('Network error: ' + e.message);
    }
  }

  form.addEventListener('submit', function (e) {
    e.preventDefault();
    startGeneration();
  });
})();
