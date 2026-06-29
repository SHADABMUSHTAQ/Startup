import React, { useCallback, useEffect, useState } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { useAuthStore } from './store/authStore';
import ProtectedRoute from './components/ProtectedRoute';
import PublicRoute from './components/PublicRoute';
import PreLoader from './assets/Components/PreLoader/PreLoader';

// Import all enterprise components for the final end-to-end wiring.
import Home from './assets/Pages/Home/Home';
import Login from './assets/Pages/Login/Login';
import Pricing from './assets/Pages/Pricing/Pricing';
import RequestQuote from './assets/Pages/RequestQuote/RequestQuote';
import Payment from './assets/Pages/Payment/Payment';
import Dashboard from './assets/Pages/Dashboard/Dashboard';
import AuditorDashboard from './assets/Pages/Auditor/AuditorDashboard';
import LegalPage from './assets/Pages/Legal/LegalPage';

function App() {
    const { checkAuth } = useAuthStore();
    const [isBooting, setIsBooting] = useState(true);
    const finishBoot = useCallback(() => setIsBooting(false), []);

    // Fire the hydration check exactly once when the app mounts.
    useEffect(() => {
        checkAuth();
    }, [checkAuth]);

    return (
        <>
            {isBooting && <PreLoader onFinish={finishBoot} />}
            <Router>
                <Routes>
                    {/* Public marketing perimeter */}
                    <Route path="/" element={<Home />} />
                    <Route path="/privacy" element={<LegalPage type="privacy" />} />
                    <Route path="/terms" element={<LegalPage type="terms" />} />
                    <Route path="/pricing" element={<Pricing standalone />} />
                    <Route path="/request-quote" element={<RequestQuote />} />

                    {/* Gateway / public route */}
                    <Route element={<PublicRoute />}>
                        <Route path="/login" element={<Login />} />
                    </Route>

                    {/* Secure SIEM interior */}
                    <Route element={<ProtectedRoute />}>
                        <Route path="/payment" element={<Payment />} />
                        <Route path="/dashboard" element={<Dashboard />} />
                        <Route path="/auditor" element={<AuditorDashboard />} />
                    </Route>

                    {/* Fallback */}
                    <Route path="*" element={<Navigate to="/" replace />} />
                </Routes>
            </Router>
        </>
    );
}

export default App;
