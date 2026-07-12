const form = document.getElementById('inviteForm');
const displayNameInput = document.getElementById('displayName');
const passwordInput = document.getElementById('password');
const confirmInput = document.getElementById('confirm');
const submitButton = document.getElementById('submit');
const errorBox = document.getElementById('err');
const successPanel = document.getElementById('success');
const acceptedUser = document.getElementById('acceptedUser');
const loginLink = document.getElementById('loginLink');
const boundedResponse = window.RedactWallAuthResponse;

const token = new URLSearchParams(String(location.hash || '').replace(/^#/, '')).get('token') || '';
// Capture the fragment in memory, then remove all URL parameters before the
// user enters a password. Legacy query-token links deliberately fail closed.
try { history.replaceState(null, document.title, location.pathname); } catch {}

function showError(message, input) {
  errorBox.textContent = message || '';
  if (message && input) input.focus();
}

function setInvalid(input, invalid) {
  input.setAttribute('aria-invalid', invalid ? 'true' : 'false');
}

if (!token) {
  showError('This invite link is missing a token. Ask your RedactWall administrator to resend it.');
  submitButton.disabled = true;
}

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  showError('');
  setInvalid(passwordInput, false);
  setInvalid(confirmInput, false);

  const password = passwordInput.value;
  if (password.length < 12) {
    setInvalid(passwordInput, true);
    showError('Password must be at least 12 characters.', passwordInput);
    return;
  }
  if (password !== confirmInput.value) {
    setInvalid(confirmInput, true);
    showError('Passwords do not match.', confirmInput);
    return;
  }

  submitButton.disabled = true;
  try {
    const response = await fetch('/api/invitations/accept', {
      method: 'POST',
      redirect: 'error',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        token,
        password,
        displayName: displayNameInput.value.trim() || undefined,
      }),
    });
    const body = await boundedResponse?.readJson(response);
    if (!response.ok) {
      showError(body?.error === 'invalid_or_expired_invitation'
        ? 'Invite is invalid, expired, already used, or revoked.'
        : 'Could not accept invite. Ask your administrator to resend it.');
      return;
    }
    if (!body || typeof body.user !== 'string' || !body.user.trim()) {
      showError('Invite acceptance could not be verified. Sign in only after your administrator confirms the account.');
      return;
    }
    const role = typeof body.roleLabel === 'string' && body.roleLabel.trim()
      ? body.roleLabel.trim()
      : typeof body.role === 'string' && body.role.trim()
        ? body.role.trim()
        : 'staff user';
    acceptedUser.textContent = `${body.user} is ready as ${role}.`;
    loginLink.href = `/login.html#user=${encodeURIComponent(body.user || '')}`;
    form.hidden = true;
    successPanel.hidden = false;
  } catch {
    showError('Network error while accepting invite. Try again.');
  } finally {
    submitButton.disabled = false;
  }
});
