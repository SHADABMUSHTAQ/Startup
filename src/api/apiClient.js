import axios from 'axios';
import { formatApiError } from '../utils/apiError';
import {
    clearUnauthorizedSession,
    getSessionCsrfToken,
} from './sessionBridge';

// 1. The Singleton Instance
const apiClient = axios.create({
    // Maps to your Vite env variable or defaults to your local backend
    baseURL: import.meta.env.VITE_API_BASE_URL || (import.meta.env.PROD ? '/api/v1' : 'http://127.0.0.1:8000/api/v1'),
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
    const csrfToken = getSessionCsrfToken();
    if (csrfToken && ['post', 'put', 'delete', 'patch'].includes(config.method)) {
        config.headers['X-CSRF-Token'] = csrfToken;
    }
    return config;
});

// 2. The Global 401 Trap
// Synchronous, hard-failing guard against unauthorized states.
apiClient.interceptors.response.use(
    (response) => response,
    (error) => {
        const status = error.response?.status;
        const reqUrl = error.config?.url ?? '';

        // 1. Initial Filter: Only intercept 401s
        if (status === 401) {
            // 2. The Whitelist Exception: Do not redirect if the failure is from login or me
            const isCredentialVerification =
                reqUrl.includes('/auth/login') ||
                reqUrl.includes('/auth/2fa/verify') ||
                reqUrl.includes('/auth/2fa/disable');
            if (!isCredentialVerification && !reqUrl.includes('/auth/me')) {
                // 3. State Eviction Sequence
                clearUnauthorizedSession();
            }
        }

        error.userMessage = formatApiError(error);

        // Maintain rejection fallthrough for all errors
        return Promise.reject(error);
    }
);

export default apiClient;
