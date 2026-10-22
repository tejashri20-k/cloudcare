// The ONE place that says where the backend lives.
// Opened locally -> talks to your local backend.
// Hosted online  -> talks to the deployed backend.
const isLocal = ['localhost', '127.0.0.1', ''].includes(window.location.hostname);

window.APP_CONFIG = {
  API_BASE: isLocal
    ? 'http://localhost:5000/api'
    : 'https://cloudcare-api.onrender.com/api'   // <-- you'll fill this in at Part 3
};