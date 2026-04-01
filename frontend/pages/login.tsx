import { useState } from "react";
import { useAuth } from "../contexts/auth";

const Login = () => {
  const { login } = useAuth();

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const handleSubmit: React.SubmitEventHandler = async (e) => {
    e.preventDefault();
    setError("");
    setLoading(true);

    if (email === "") {
      setError("Email is required");
      return;
    }
    if (password === "") {
      setError("Password is required");
      return;
    }

    try {
      await login({ email: email.trim(), password: password });
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex flex-col items-center mt-10">
      <h2 className="text-xl mb-4">Login</h2>
      <form onSubmit={handleSubmit} className="flex flex-col gap-2 w-64">
        <input
          className="border p-2 rounded"
          placeholder="Email"
          type="email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
        />
        <input
          className="border p-2 rounded"
          placeholder="Password"
          type={showPassword ? "text" : "password"}
          value={password}
          onChange={(e) => setPassword(e.target.value)}
        />
        <div className="flex gap-1">
          <input
            type="checkbox"
            id="show-password-checkbox"
            onChange={(evt) => setShowPassword(evt.currentTarget.checked)}
          />
          <label htmlFor="show-password-checkbox">Show password</label>
        </div>
        <a
          href="/forgot-password"
          className="text-right underline hover:text-blue-500"
        >
          Forgot password?
        </a>
        {error && <p className="text-red-500 text-sm">{error}</p>}
        <button
          type="submit"
          disabled={loading}
          className="bg-blue-500 text-white p-2 rounded cursor-pointer"
        >
          {loading ? "Logging in..." : "Login"}
        </button>
      </form>
      <span>
        Don't have an account yet?{" "}
        <a
          className="hover:text-blue-500 underline cursor-pointer"
          href="/register"
        >
          Register here
        </a>
        .
      </span>
    </div>
  );
};

export { Login };
