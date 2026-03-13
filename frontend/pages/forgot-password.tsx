import { useState } from "react";

const ForgotPassword = () => {
  const [email, setEmail] = useState("");
  const [isSent, setIsSent] = useState(false);
  const [error, setError] = useState("");

  const handleSubmit: React.SubmitEventHandler = async (e) => {
    e.preventDefault();
    setError("");

    if (email === "") {
      setError("Email is required");
      return;
    }

    try {
      const res = await fetch("http://localhost:8080/api/password-reset-link", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          email: email,
        }),
      });
      if (res.status === 200) {
        console.log("Link to reset password is sent to the email address!");
        setIsSent(true);
      } else {
        throw new Error(
          "Send password reset link failed with status " + res.status + "!",
        );
      }
    } catch (err) {
      console.error(err);
      setError((err as Error).message);
    }
  };

  return (
    <div className="flex flex-col items-center mt-10">
      <h2 className="text-xl mb-4">Forgot Password</h2>
      <form className="flex flex-col gap-2 w-64" onSubmit={handleSubmit}>
        <input
          className="border p-2 rounded"
          placeholder="Email"
          type="email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
        />
        <span className="text-[10px]">
          You will recieve a password reset link on this email address. You can
          reset the password with it.
        </span>
        {isSent ? (
          <p className="text-green-500 text-sm">
            Password reset link has been sent to your email address!
          </p>
        ) : (
          <button
            type="submit"
            className="bg-blue-500 text-white p-2 rounded cursor-pointer"
          >
            Send
          </button>
        )}
        {error && <p className="text-red-500 text-sm">{error}</p>}
      </form>
    </div>
  );
};

export { ForgotPassword };
