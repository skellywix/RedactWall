const f = document.getElementById('f');
const userInput = document.getElementById('user');
const passwordInput = document.getElementById('password');
const otpInput = document.getElementById('otp');
const errorBox = document.getElementById('err');
const oidcButton = document.getElementById('oidc');
const demoHint = document.getElementById('demoHint');
const params = new URLSearchParams(location.search);
const fragmentParams = new URLSearchParams(String(location.hash || '').replace(/^#/, ''));

const invitedUser = fragmentParams.get('user');
if (invitedUser) userInput.value = invitedUser;

// Invite identity is a convenience hint, not request metadata. Capture it from
// the fragment, then remove it before credentials are entered or links can
// propagate it. Legacy ?user= links are ignored and stripped because their
// request target may already have appeared in access logs.
if (location.hash || params.has('user')) {
  const safeSearch = params.get('oidc') === 'failed' ? '?oidc=failed' : '';
  try { history.replaceState(null, document.title, location.pathname + safeSearch); } catch {}
}

if (params.get('oidc') === 'failed') {
  showError('SSO sign-in failed. Try again or use a local account.');
}

function setInvalidFields(fields = []) {
  const invalid = new Set(fields);
  [
    ['user', userInput],
    ['password', passwordInput],
    ['otp', otpInput],
  ].forEach(([name, input]) => {
    input.setAttribute('aria-invalid', invalid.has(name) ? 'true' : 'false');
  });
}

function showError(message, fields = []) {
  errorBox.textContent = message || '';
  setInvalidFields(fields);
}

async function loadLoginOptions() {
  try {
    const r = await fetch('/api/login-options');
    if (!r.ok) return;
    const body = await r.json();
    if (body.oidc && body.oidc.enabled && body.oidc.startUrl) {
      oidcButton.hidden = false;
      oidcButton.onclick = () => {
        location.href = body.oidc.startUrl;
      };
    }
    // Only advertise the demo credential while it actually works.
    if (demoHint && body.defaultAdminCredential === true) demoHint.hidden = false;
  } catch {}
}

loadLoginOptions();

f.addEventListener('submit', async (e) => {
  e.preventDefault();
  showError('');
  const r = await fetch('/api/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ user: userInput.value, password: passwordInput.value, otp: otpInput.value }),
  });
  if (r.ok) location.href = '/app/';
  else {
    const body = await r.json().catch(() => ({}));
    if (body.mfaRequired) showError('Enter the current authenticator code.', ['otp']);
    else showError('Invalid credentials. Try again.', ['user', 'password']);
  }
});
