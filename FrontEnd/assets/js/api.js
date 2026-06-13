// api.js
const API_BASE_URL = '/api';

async function fetchFromApi(endpoint, options = {}) {
    // Basic fetch wrapper
    const response = await fetch(`${API_BASE_URL}${endpoint}`, options);
    return response.json();
}
