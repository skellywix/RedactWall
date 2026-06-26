const f = document.getElementById('f');
  f.addEventListener('submit', async (e) => {
    e.preventDefault();
    document.getElementById('err').textContent = '';
    const r = await fetch('/api/login', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ user: user.value, password: password.value })
    });
    if (r.ok) { location.href = '/index.html'; }
    else { document.getElementById('err').textContent = 'Invalid credentials. Try again.'; }
  });

