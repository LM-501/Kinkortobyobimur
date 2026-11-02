/* login.html এর জন্য: লগইন ও রেজিস্টার ফর্ম */
const $ = (id) => document.getElementById(id);
let mode = 'login'; // 'login' বা 'register'

function setMode(m) {
  mode = m;
  $('tabLogin').classList.toggle('on', m === 'login');
  $('tabReg').classList.toggle('on', m === 'register');
  $('p2wrap').hidden = m === 'login';
  $('p2').required = m === 'register';
  $('p').autocomplete = m === 'login' ? 'current-password' : 'new-password';
  $('go').textContent = m === 'login' ? 'লগইন' : 'একাউন্ট খুলুন';
  $('msg').textContent = '';
}

$('tabLogin').onclick = () => setMode('login');
$('tabReg').onclick = () => setMode('register');

$('eye').onclick = () => {
  const show = $('p').type === 'password';
  $('p').type = show ? 'text' : 'password';
  $('eye').textContent = show ? 'লুকান' : 'দেখান';
};

$('form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const msg = $('msg');
  msg.className = '';
  msg.textContent = '';

  if (mode === 'register' && $('p').value !== $('p2').value) {
    msg.textContent = 'দুটি পাসওয়ার্ড মিলছে না';
    return;
  }

  $('go').disabled = true;
  try {
    const res = await fetch('/api/' + mode, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: $('u').value.trim(), password: $('p').value }),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      msg.textContent = data.error || 'কিছু একটা ভুল হয়েছে';
    } else {
      msg.className = 'ok';
      msg.textContent = 'সফল! ঢুকছি...';
      location.href = '/app.html';
    }
  } catch (err) {
    msg.textContent = 'সার্ভারের সাথে যোগাযোগ হচ্ছে না';
  } finally {
    $('go').disabled = false;
  }
});
