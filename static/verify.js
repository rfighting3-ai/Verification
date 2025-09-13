// static/verify.js
(function(){
  const TOKEN = window.AEGIS_TOKEN || (new URLSearchParams(window.location.search)).get('token') || 'demo-token';

  let mouseIntervals = [];
  let lastMouse = null;
  let typingIntervals = [];
  let lastKey = null;
  let honeypotTouched = false;

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
    if (lastMouse) {
      mouseIntervals.push(t - lastMouse);
    }
    lastMouse = t;
  });

  const input = document.getElementById('typed');
  input.addEventListener('keydown', (e) => {
    const t = Date.now();
    if (lastKey) {
      typingIntervals.push(t - lastKey);
    }
    lastKey = t;
  });

  window.addEventListener('scroll', () => {
    const t = Date.now();
    if (lastMouse) mouseIntervals.push(t - lastMouse);
    lastMouse = t;
  });

  setTimeout(() => {
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
    }).then(res => res.json()).then(j => {
      document.getElementById('status').innerText = 'Verification submitted — please return to Discord.';
    }).catch(err => {
      document.getElementById('status').innerText = 'Submit failed — try again.';
      console.error(err);
    });
  }, 3000 + Math.random()*2000);

})();
