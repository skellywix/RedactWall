const f = document.getElementById('f');
const userInput = document.getElementById('user');
const passwordInput = document.getElementById('password');
const otpInput = document.getElementById('otp');
const errorBox = document.getElementById('err');
const oidcButton = document.getElementById('oidc');

if (new URLSearchParams(location.search).get('oidc') === 'failed') {
  errorBox.textContent = 'SSO sign-in failed. Try again or use a local account.';
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
  errorBox.textContent = '';
  const r = await fetch('/api/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ user: userInput.value, password: passwordInput.value, otp: otpInput.value }),
  });
  if (r.ok) location.href = '/index.html';
  else {
    const body = await r.json().catch(() => ({}));
    errorBox.textContent = body.mfaRequired
      ? 'Enter the current authenticator code.'
      : 'Invalid credentials. Try again.';
  }
});
