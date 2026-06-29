import React from 'react';
import { Navigate, Outlet } from 'react-router-dom';
import { useAuthStore } from '../store/authStore';

const PublicRoute = () => {
    const { isAuthenticated, isLoading } = useAuthStore();

    // 🛡️ The Hydration Barrier: Wait for the /auth/me ping to resolve
    if (isLoading) {
        return (
            <div className="flex h-screen items-center justify-center bg-[#0a0f1c] text-white">
                <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-blue-500"></div>
                <span className="ml-4 font-mono">Verifying Session...</span>
            </div>
        );
    }

    // 🚫 Reverse Bounce: Already logged in? Kick back to dashboard.
    if (isAuthenticated) {
        return <Navigate to="/dashboard" replace />;
    }

    return <Outlet />;
};

export default PublicRoute;
