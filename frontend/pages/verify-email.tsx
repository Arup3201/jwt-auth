import { useEffect, useState } from "react";
import { useSearchParams } from "react-router";

const VerifyEmail = () => {
  const [searchParams, _] = useSearchParams();
  const email = searchParams.get("email");

  const [isVerified, setIsVerified] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    if (!email || email === "") return;

    (async function () {
      try {
        const response = await fetch(
          `http://localhost:8080/api/email-verified?email=${email}`,
        );
        if (response.status === 200) {
          const json = await response.json();
          if (json.is_verified) {
            setIsVerified(true);
          } else {
            setIsVerified(false);
          }
        } else {
          throw new Error(
            "API request for message failed with status " + response.status,
          );
        }
      } catch (err) {
        console.error(err);
        setError((err as Error).message);
      }
    })();
  }, [email]);

  if (!email || email === "") {
    return (
      <div className="flex flex-col items-center mt-5 mx-auto max-w-[900px] border border-red-50">
        <h2 className="w-full text-center bg-slate-50 text-xl mb-4">Error</h2>
        <p>Missing email address to check verification status.</p>
      </div>
    );
  }

  if (error !== "") {
    return (
      <div className="flex flex-col items-center mt-5 mx-auto max-w-[900px] border border-red-50">
        <h2 className="w-full text-center bg-slate-50 text-xl mb-4">Error</h2>
        <p>Encountered an error while fetching the verification status.</p>
        <span className="text-red-500">{error}</span>
      </div>
    );
  }

  return isVerified ? (
    <div className="flex flex-col items-center mt-5 mx-auto max-w-[900px] border border-green-50">
      <h2 className="w-full text-center bg-green-50 text-xl mb-4">
        Email Verified
      </h2>
      <p>
        Your email has been verified successfully. You can{" "}
        <a className="underline text-blue-500" href="/login">
          login
        </a>{" "}
        to the site now.
      </p>
    </div>
  ) : (
    <div className="flex flex-col items-center mt-5 mx-auto max-w-[900px] border border-red-50">
      <h2 className="w-full text-center bg-red-50 text-xl mb-4">
        Pending Email Verification
      </h2>
      <p>
        Your email is not yet verified. Check your email inbox for the
        verification email and verify your email address.
      </p>
      <em>
        In case you did not receive the verification email or it has been
        expired.
      </em>
      <button className="mb-5 underline cursor-pointer text-blue-500 hover:text-blue-700">
        Resend verification email
      </button>
    </div>
  );
};

export { VerifyEmail };
