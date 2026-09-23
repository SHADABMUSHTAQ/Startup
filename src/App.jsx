import React, { lazy, Suspense, useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { useAuthStore } from './store/authStore';
import ProtectedRoute from './components/ProtectedRoute';
import PublicRoute from './components/PublicRoute';
import ErrorBoundary from './components/ErrorBoundary';
import SessionLoading from './components/SessionLoading';
import CustomCursor from './assets/Components/CustomCursor/CustomCursor';

const Home = lazy(() => import('./assets/Pages/Home/Home'));
const Login = lazy(() => import('./assets/Pages/Login/Login'));
const SetPassword = lazy(() => import('./assets/Pages/SetPassword/SetPassword'));
const Pricing = lazy(() => import('./assets/Pages/Pricing/Pricing'));
const RequestQuote = lazy(() => import('./assets/Pages/RequestQuote/RequestQuote'));
const Dashboard = lazy(() => import('./assets/Pages/Dashboard/Dashboard'));
const Profile = lazy(() => import('./assets/Pages/Profile/Profile'));
const LegalPage = lazy(() => import('./assets/Pages/Legal/LegalPage'));

function App() {
    const { checkAuth } = useAuthStore();

    // Fire the hydration check exactly once when the app mounts.
    useEffect(() => {
        checkAuth();
    }, [checkAuth]);

    return (
        <ErrorBoundary>
            <CustomCursor />
            <Router>
                <Suspense fallback={<SessionLoading />}>
                    <Routes>
                        {/* Public marketing perimeter */}
                        <Route path="/" element={<Home />} />
                        <Route path="/privacy" element={<LegalPage type="privacy" />} />
                        <Route path="/terms" element={<LegalPage type="terms" />} />
                        <Route path="/pricing" element={<Pricing standalone />} />
                        <Route path="/request-quote" element={<RequestQuote />} />
                        <Route path="/set-password" element={<SetPassword />} />

                        {/* Gateway / public route */}
                        <Route element={<PublicRoute />}>
                            <Route path="/login" element={<Login />} />
                        </Route>

                        {/* Secure SIEM interior */}
                        <Route element={<ProtectedRoute />}>
                            <Route path="/profile" element={<Profile />} />
                            <Route path="/dashboard" element={<Dashboard />} />
                        </Route>

                        {/* Fallback */}
                        <Route path="*" element={<Navigate to="/" replace />} />
                    </Routes>
                </Suspense>
            </Router>
        </ErrorBoundary>
    );
}

export default App;
