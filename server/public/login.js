const f = document.getElementById('f');
const userInput = document.getElementById('user');
const passwordInput = document.getElementById('password');
const otpInput = document.getElementById('otp');
const submitButton = document.getElementById('submit');
const errorBox = document.getElementById('err');
const oidcButton = document.getElementById('oidc');
const demoHint = document.getElementById('demoHint');
const params = new URLSearchParams(location.search);
const fragmentParams = new URLSearchParams(String(location.hash || '').replace(/^#/, ''));
const boundedResponse = window.RedactWallAuthResponse;
let submitting = false;

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
  if (message && fields.length) {
    const firstInvalid = { user: userInput, password: passwordInput, otp: otpInput }[fields[0]];
    firstInvalid?.focus();
  }
}

async function loadLoginOptions() {
  try {
    const r = await fetch('/api/login-options', { redirect: 'error' });
    if (!r.ok) return;
    const body = await boundedResponse?.readJson(r);
    if (body?.oidc?.enabled === true && body.oidc.startUrl === '/auth/oidc/start') {
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
passwordInput.focus();

f.addEventListener('submit', async (e) => {
  e.preventDefault();
  if (submitting) return;
  submitting = true;
  submitButton.disabled = true;
  f.setAttribute('aria-busy', 'true');
  showError('');
  let completed = false;
  try {
    const r = await fetch('/api/login', {
      method: 'POST',
      redirect: 'error',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ user: userInput.value, password: passwordInput.value, otp: otpInput.value }),
    });
    if (r.ok) {
      try { void r.body?.cancel(); } catch {}
      completed = true;
      location.href = '/app/';
      return;
    }
    const body = await boundedResponse?.readJson(r);
    if (body?.mfaRequired === true) {
      showError('Enter your current authenticator or recovery code.', ['otp']);
    } else {
      showError('Invalid credentials. Try again.', ['user', 'password']);
    }
  } catch {
    showError('Sign-in service is unavailable. Try again.', ['user', 'password']);
  } finally {
    if (!completed) {
      submitting = false;
      submitButton.disabled = false;
      f.removeAttribute('aria-busy');
    }
  }
});
