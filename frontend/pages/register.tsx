import { useState } from "react";
import { useAuth } from "../contexts/auth";

const Register = () => {
  const { register } = useAuth();

  const [email, setEmail] = useState("");
  const [name, setName] = useState("");
  const [password, setPassword] = useState("");
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
    if (name === "") {
      setError("Full name is required");
      return;
    }
    if (password === "") {
      setError("Password is required");
      return;
    }

    try {
      await register({
        email: email.trim(),
        name: name.trim(),
        password: password,
      });
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
          placeholder="Full Name"
          value={name}
          onChange={(e) => setName(e.target.value)}
        />
        <input
          className="border p-2 rounded"
          placeholder="Password"
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
        />
        {error && <p className="text-red-500 text-sm">{error}</p>}
        <button
          type="submit"
          disabled={loading}
          className="bg-blue-500 text-white p-2 rounded cursor-pointer"
        >
          {!loading ? "Register" : "Registering..."}
        </button>
      </form>

      <span>
        Already have an account?{" "}
        <a
          className="hover:text-blue-500 underline cursor-pointer"
          href="/login"
        >
          Login here
        </a>
        .
      </span>
    </div>
  );
};

export { Register };
