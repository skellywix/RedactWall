const f = document.getElementById('f');
const userInput = document.getElementById('user');
const passwordInput = document.getElementById('password');
const errorBox = document.getElementById('err');

f.addEventListener('submit', async (e) => {
  e.preventDefault();
  errorBox.textContent = '';
  const r = await fetch('/api/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ user: userInput.value, password: passwordInput.value }),
  });
  if (r.ok) location.href = '/index.html';
  else errorBox.textContent = 'Invalid credentials. Try again.';
});
