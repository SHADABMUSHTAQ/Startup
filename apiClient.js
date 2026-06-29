import axios from 'axios';
import { useAuthStore } from '../store/authStore';

// 1. The Singleton Instance
const apiClient = axios.create({
    // Maps to your Vite env variable or defaults to your local backend
    baseURL: import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000/api/v1',
    // 🛡️ CRITICAL: This forces the browser to send the HttpOnly cookie automatically
    withCredentials: true, 
    // ⏱️ Anti-Infinite-Spinner: Hard timeout (10s) for network drops
    timeout: 10000,
    headers: {
        'Content-Type': 'application/json',
    }
});

// 🛡️ CSRF Token Interceptor (Double-Submit Header Pattern)
apiClient.interceptors.request.use((config) => {
    // Grab the ephemeral CSRF token from memory state (not localStorage)
    const csrfToken = useAuthStore.getState().csrfToken;
    if (csrfToken && ['post', 'put', 'delete', 'patch'].includes(config.method)) {
        config.headers['X-CSRF-Token'] = csrfToken;
    }
    return config;
});

// 2. The Global 401 Trap
apiClient.interceptors.response.use(
    (response) => response,
    (error) => {
        // If the backend rejects the cookie (expired, blacklisted, etc.)
        if (error.response && error.response.status === 401) {
            console.warn("Unauthorized API call intercepted. Purging state.");
            useAuthStore.getState().logout();
        }
        return Promise.reject(error);
    }
);

export default apiClient;