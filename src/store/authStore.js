import { create } from 'zustand';
import apiClient from '../api/apiClient';

export const useAuthStore = create((set) => ({
    user: null,
    plan_type: null,
    role: null,
    isAuthenticated: false,
    csrfToken: null, // Ephemeral memory storage for CSRF validation
    
    // 🛡️ State Hydration: Starts true so the app doesn't flash the login screen on refresh
    isLoading: true, 

    checkAuth: async () => {
        try {
            const response = await apiClient.get('/auth/me');
            set({
                user: response.data.user,
                plan_type: response.data.plan_type,
                role: response.data.role,
                isAuthenticated: true,
                csrfToken: response.data.csrf_token || null,
                isLoading: false,
            });
        } catch (error) {
            // Cookie is dead or missing
            set({
                user: null,
                plan_type: null,
                role: null,
                isAuthenticated: false,
                csrfToken: null,
                isLoading: false,
            });
        }
    },

    logout: async () => {
        try {
            // Tell the backend to kill the Redis session/cookie
            await apiClient.post('/auth/logout');
        } catch (error) {
            console.error("Logout request failed, wiping local state anyway", error);
        } finally {
            // Instantly wipe all client state
            set({
                user: null,
                plan_type: null,
                role: null,
                isAuthenticated: false,
                csrfToken: null,
            });
            window.location.href = '/login'; // Hard redirect clears lingering memory
        }
    }
}));
