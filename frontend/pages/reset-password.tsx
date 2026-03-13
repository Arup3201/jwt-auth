import { useState } from "react";
import { useSearchParams } from "react-router";

const ResetPassword = () => {
  const [searchParams, _] = useSearchParams();
  const token = searchParams.get("token");

  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState("");
  const [hasReset, setHasReset] = useState(false);

  const handleSubmit: React.SubmitEventHandler = async (e) => {
    e.preventDefault();
    setError("");

    if (password === "") {
      setError("Password is required");
      return;
    }

    if (password !== confirmPassword) {
      setError("Passwords must match");
      return;
    }

    try {
      const res = await fetch("http://localhost:8080/api/reset-password", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          token: token,
          password: password,
        }),
      });
      if (res.status === 200) {
        setHasReset(true);
      } else {
        throw new Error(
          "Reset password failed with status " + res.status + "!",
        );
      }
    } catch (err) {
      console.error(err);
      setError((err as Error).message);
    }
  };

  if (!token || token === "") {
    return (
      <div className="flex flex-col items-center mt-5 mx-auto max-w-[900px] border border-red-50">
        <h2 className="w-full text-center bg-slate-50 text-xl mb-4">Error</h2>
        <p>Missing reset password token.</p>
      </div>
    );
  }

  return (
    <div className="flex flex-col items-center mt-10">
      <h2 className="text-xl mb-4">Reset Password</h2>
      <form className="flex flex-col gap-2 w-64" onSubmit={handleSubmit}>
        <input
          className="border p-2 rounded"
          placeholder="Password"
          type={showPassword ? "text" : "password"}
          value={password}
          onChange={(e) => setPassword(e.target.value)}
        />
        <input
          className="border p-2 rounded"
          placeholder="Confirm Password"
          type={showPassword ? "text" : "password"}
          value={confirmPassword}
          onChange={(e) => setConfirmPassword(e.target.value)}
        />
        <div className="flex gap-1">
          <input
            type="checkbox"
            id="show-password-checkbox"
            onChange={(evt) => setShowPassword(evt.currentTarget.checked)}
          />
          <label htmlFor="show-password-checkbox">Show password</label>
        </div>
        {hasReset ? (
          <>
            <p className="text-green-500 text-sm">Password reset successful!</p>
            <span className="text-[10px]">
              After password reset, your all sessions will be invalidated. You
              have to{" "}
              <a
                className="text-right underline hover:text-blue-500"
                href="/login"
              >
                login
              </a>{" "}
              again.
            </span>
          </>
        ) : (
          <button
            type="submit"
            className="bg-blue-500 text-white p-2 rounded cursor-pointer"
          >
            Reset
          </button>
        )}
        {error && <p className="text-red-500 text-sm">{error}</p>}
      </form>
    </div>
  );
};

export { ResetPassword };
