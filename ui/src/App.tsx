import { BrowserRouter as Router, Routes, Route } from 'react-router';

import { AuthProvider } from "../hooks/useAuth"
import { Navbar } from '../components/navbar'
import { ProtectedRoute } from '../components/protected'

import { Login } from '../pages/login'
import { Home } from '../pages/home'
import { About } from '../pages/about'
import { Dashboard } from '../pages/dashboard'
import { Settings } from '../pages/settings'

const App = () => {
  return (
    <Router>
      <AuthProvider>
        <Navbar />
        <div className="p-4">
          <Routes>
            <Route index element={<Home />} />
            <Route path="/about" element={<About />} />
            <Route path="/login" element={<Login />} />
            <Route
              path="/dashboard"
              element={
                <ProtectedRoute>
                  <Dashboard />
                </ProtectedRoute>
              }
            />
            <Route
              path="/settings"
              element={
                <ProtectedRoute>
                  <Settings />
                </ProtectedRoute>
              }
            />
          </Routes>
        </div>
      </AuthProvider>
    </Router>
  );
};


export default App;
