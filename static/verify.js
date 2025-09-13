// static/verify.js
(function(){
  const TOKEN = window.AEGIS_TOKEN || (new URLSearchParams(window.location.search)).get('token') || null;
  if (!TOKEN) {
    document.getElementById('msg').innerText = 'Missing token — open the link provided by Discord.';
    return;
  }

  let mouseIntervals = [];
  let lastMouse = null;
  let typingIntervals = [];
  let lastKey = null;
  let honeypotTouched = false;
  const statusEl = document.getElementById('msg');
  const reasonBox = document.getElementById('reasonBox');
  const reasonEl = document.getElementById('reason');

  // honeypot hidden field
  const hp = document.createElement('input');
  hp.type = 'text';
  hp.id = 'hp_trap';
  hp.value = '';
  hp.style.position = 'absolute';
  hp.style.left = '-9999px';
  document.body.appendChild(hp);
  hp.addEventListener('focus', () => { honeypotTouched = true; });

  window.addEventListener('mousemove', (e) => {
    const t = Date.now();
    if (lastMouse) mouseIntervals.push(t - lastMouse);
    lastMouse = t;
  });

  const input = document.getElementById('typed');
  input.addEventListener('keydown', (e) => {
    const t = Date.now();
    if (lastKey) typingIntervals.push(t - lastKey);
    lastKey = t;
  });

  window.addEventListener('scroll', () => {
    const t = Date.now();
    if (lastMouse) mouseIntervals.push(t - lastMouse);
    lastMouse = t;
  });

  function showPending() {
    statusEl.innerHTML = 'Submitting… <span id="spinner"></span>';
  }
  function showSuccess(text, details) {
    statusEl.innerHTML = '<span class="success">Verification successful ✓</span>';
    if (details) {
      reasonBox.style.display = 'block';
      reasonEl.innerText = details;
    }
  }
  function showQuarantine(text, details) {
    statusEl.innerHTML = '<span class="danger">Quarantined ⚠️</span>';
    if (details) {
      reasonBox.style.display = 'block';
      reasonEl.innerText = details;
    }
  }
  function showError(text) {
    statusEl.innerHTML = '<span class="danger">Error: ' + text + '</span>';
  }

  function disableInputs() {
    input.disabled = true;
  }

  // prepare payload and POST to /submit
  function submitOnce() {
    showPending();

    const fp = {
      ua: navigator.userAgent,
      platform: navigator.platform,
      lang: navigator.language,
      screen: [screen.width, screen.height, screen.pixelDepth]
    };

    const dna = {
      typing: typingIntervals.slice(0, 40),
      mouse: mouseIntervals.slice(0, 200),
      tz: Intl.DateTimeFormat().resolvedOptions().timeZone || null
    };

    const payload = {
      token: TOKEN,
      fp: JSON.stringify(fp),
      dna: dna,
      honeypot: honeypotTouched
    };

    fetch('/submit', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(payload)
    }).then(async res => {
      const j = await res.json().catch(()=>({ok:false, error:'invalid json'}));
      if (res.status === 200 && j.ok) {
        // start polling status
        disableInputs();
        pollStatus();
      } else {
        disableInputs();
        showError(j.error || ('HTTP ' + res.status));
      }
    }).catch(err => {
      disableInputs();
      showError('Network error');
      console.error(err);
    });
  }

  // poll the status endpoint for token until a definitive state or timeout
  let polls = 0;
  const POLL_INTERVAL = 1000; // 1s
  const MAX_POLLS = 30; // 30s
  async function pollStatus(){
    try {
      const res = await fetch(`/status/${encodeURIComponent(TOKEN)}`, {method:'GET'});
      if (res.status === 200) {
        const j = await res.json();
        if (j.ok) {
          const s = j.status || 'pending';
          // j.action and j.reason available
          if (s === 'verified' || j.action === 'verified') {
            showSuccess('Verified', j.reason || ('score info: ' + (j.reason || 'N/A')));
            return;
          }
          // check if quarantine action present or token used
          if (j.action && (j.action.toLowerCase().includes('quarantine') || j.action.toLowerCase().includes('quarantine_auto'))) {
            showQuarantine('Quarantined', j.reason || '');
            return;
          }
          if (j.action && j.action.toLowerCase().includes('ban')) {
            showQuarantine('Banned', j.reason || '');
            return;
          }
          if (j.used) {
            // used but not verified (maybe expired or reused)
            showError('Token already used or expired. Check Discord or contact a moderator.');
            return;
          }
          // still pending
        } else {
          showError(j.error || 'Unknown response');
          return;
        }
      } else if (res.status === 404) {
        showError('Verification token not found or expired.');
        return;
      } else {
        // non-200 — continue polling but show a message
        statusEl.innerText = 'Waiting for verification results…';
      }
    } catch (err) {
      console.error('poll error', err);
      statusEl.innerText = 'Waiting for verification results…';
    }
    polls++;
    if (polls >= MAX_POLLS) {
      statusEl.innerText = 'Still pending — verification may take longer. Check Discord or contact a moderator.';
      return;
    }
    setTimeout(pollStatus, POLL_INTERVAL);
  }

  // wait a bit for user interactions then submit
  setTimeout(() => {
    document.getElementById('challenge').innerText = Math.random().toString(36).substring(2,6).toUpperCase();
    submitOnce();
  }, 1800 + Math.random()*1600);
})();
