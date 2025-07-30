import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider } from './hooks/useAuth';
import { PrivateRoute } from './components/PrivateRoute';
import { SignUp } from './pages/SignUp';
import { SignIn } from './pages/SignIn';
import { Profile } from './pages/Profile';
import { MobileAuth } from './pages/MobileAuth';
import SecuritySettings from './pages/SecuritySettings';
import VerifyEmail from './pages/VerifyEmail';
import { ForgotPassword } from './pages/ForgotPassword';
import { ResetPassword } from './pages/ResetPassword';
import { useCsrfToken, configureAxiosCSRF } from './hooks/useCsrfToken';
import { useTokenRefresh } from './hooks/useTokenRefresh';
import { useEffect } from 'react';

function AppContent() {
  useTokenRefresh();
  
  return (
    <Router>
        <Routes>
          <Route path="/signup" element={<SignUp />} />
          <Route path="/signin" element={<SignIn />} />
          <Route path="/verify-email" element={<VerifyEmail />} />
          <Route path="/mobile-auth" element={<MobileAuth />} />
          <Route path="/forgot-password" element={<ForgotPassword />} />
          <Route path="/reset-password" element={<ResetPassword />} />
          <Route
            path="/profile"
            element={
              <PrivateRoute>
                <Profile />
              </PrivateRoute>
            }
          />
          <Route
            path="/security"
            element={
              <PrivateRoute>
                <SecuritySettings />
              </PrivateRoute>
            }
          />
          <Route path="/" element={<Navigate to="/signin" replace />} />
        </Routes>
      </Router>
  );
}

function App() {
  const csrfToken = useCsrfToken();

  useEffect(() => {
    if (csrfToken) {
      configureAxiosCSRF(csrfToken);
      // Store in window for immediate access
      (window as any).csrfToken = csrfToken;
    }
  }, [csrfToken]);

  return (
    <AuthProvider>
      <AppContent />
    </AuthProvider>
  );
}

export default App;