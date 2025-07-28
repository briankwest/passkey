import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider } from './hooks/useAuth';
import { PrivateRoute } from './components/PrivateRoute';
import { SignUp } from './pages/SignUp';
import { SignIn } from './pages/SignIn';
import { Profile } from './pages/Profile';
import { MobileAuth } from './pages/MobileAuth';

function App() {
  return (
    <AuthProvider>
      <Router>
        <Routes>
          <Route path="/signup" element={<SignUp />} />
          <Route path="/signin" element={<SignIn />} />
          <Route path="/mobile-auth" element={<MobileAuth />} />
          <Route
            path="/profile"
            element={
              <PrivateRoute>
                <Profile />
              </PrivateRoute>
            }
          />
          <Route path="/" element={<Navigate to="/signin" replace />} />
        </Routes>
      </Router>
    </AuthProvider>
  );
}

export default App;