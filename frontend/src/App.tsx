import { BrowserRouter as Router, Routes, Route } from "react-router";

import { Register } from "../pages/register";
import { Login } from "../pages/login";
import { VerifyEmail } from "../pages/verify-email";
import { ForgotPassword } from "../pages/forgot-password";
import { ResetPassword } from "../pages/reset-password";
import { Protected } from "../components/protected";
import { Home } from "../pages/home";
import { AuthProvider } from "../contexts/auth";

const App = () => {
  return (
    <Router>
      <AuthProvider>
        <Routes>
          <Route path="/register" element={<Register />} />
          <Route path="/login" element={<Login />} />
          <Route path="/verify-email" element={<VerifyEmail />} />
          <Route path="/forgot-password" element={<ForgotPassword />} />
          <Route path="/reset-password" element={<ResetPassword />} />
          <Route element={<Protected />}>
            <Route index element={<Home />} />
          </Route>
        </Routes>
      </AuthProvider>
    </Router>
  );
};

export default App;
