// Shared helper: sends the login token with every request to the backend.
// If the token is missing or expired, the user is sent back to the login page.
let redirectingToLogin = false;

async function authFetch(url, options = {}) {
  const token = localStorage.getItem('token');
  const headers = { ...(options.headers || {}) };
  if (token) headers['Authorization'] = 'Bearer ' + token;

  const res = await fetch(url, { ...options, headers });

  if (res.status === 401) {
    if (!redirectingToLogin) {
      redirectingToLogin = true;
      localStorage.removeItem('user');
      localStorage.removeItem('token');
      alert('Your session has expired. Please log in again.');
      window.location.replace('login.html');
    }
    throw new Error('Session expired');
  }

  return res;
}