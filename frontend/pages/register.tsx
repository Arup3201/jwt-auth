import { useState } from "react";
import { useNavigate } from "react-router";

const Register = () => {
  const navigate = useNavigate();

  const [email, setEmail] = useState("");
  const [name, setName] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");

  const handleSubmit: React.SubmitEventHandler = async (e) => {
    e.preventDefault();
    setError("");

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
      const res = await fetch("http://localhost:8080/api/auth/register", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          email: email,
          full_name: name,
          password: password,
        }),
      });
      if (res.status === 201) {
        console.log("User created!");
        navigate(`/verify-email?email=${email}`);
      } else {
        throw new Error(
          "User registration failed with status" + res.status + "!",
        );
      }
    } catch (err) {
      console.error(err);
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
          className="bg-blue-500 text-white p-2 rounded cursor-pointer"
        >
          Register
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
