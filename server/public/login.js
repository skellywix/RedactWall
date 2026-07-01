const f = document.getElementById('f');
const userInput = document.getElementById('user');
const passwordInput = document.getElementById('password');
const otpInput = document.getElementById('otp');
const errorBox = document.getElementById('err');
const oidcButton = document.getElementById('oidc');

if (new URLSearchParams(location.search).get('oidc') === 'failed') {
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
  if (r.ok) location.href = '/index.html';
  else {
    const body = await r.json().catch(() => ({}));
    if (body.mfaRequired) showError('Enter the current authenticator code.', ['otp']);
    else showError('Invalid credentials. Try again.', ['user', 'password']);
  }
});
