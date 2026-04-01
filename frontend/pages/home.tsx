import { useEffect, useState } from "react";
import { ApiFetch } from "../utils/api";

interface User {
  id: string;
  email: string;
  fullName: string;
  createdAt: string;
}

const Home = () => {
  const [serverMessage, setServerMessage] = useState<string | null>(null);
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function getUserInfo() {
    setIsLoading(true);
    setError(null);

    try {
      const res = await ApiFetch("/user-info");
      const userInfo = await res.json();
      if (userInfo) {
        setUser({
          id: userInfo.id,
          email: userInfo.email,
          fullName: userInfo.full_name,
          createdAt: userInfo.created_at,
        });
      } else {
        throw new Error("Failed to get user information");
      }
    } catch (err) {
      if (err instanceof Error) setError(err.message);
      else setError("Unknown error occured during user information fetch");
    } finally {
      setIsLoading(false);
    }
  }

  useEffect(() => {
    (async function () {
      try {
        const response = await ApiFetch("/message");
        const data = await response.json();
        if (data.message) {
          setServerMessage(data.message);
        } else {
          throw new Error("No message received");
        }
      } catch (err) {
        console.error(err);
      }
    })();
  }, []);

  return (
    <div className="space-y-2 p-8">
      <section className="border border-blue-500 p-2 rounded">
        <p>
          Server says: <em>{serverMessage || ""}</em>
        </p>
      </section>

      <button
        onClick={getUserInfo}
        disabled={isLoading}
        className="bg-blue-500 text-white text-sm p-2 rounded cursor-pointer"
      >
        {isLoading ? "Requesting..." : "Request User Information"}
      </button>

      <section className="border border-blue-500 p-2 rounded">
        {error && <p className="text-red-500 text-sm">{error}</p>}
        <p>User: {user ? <code>{JSON.stringify(user)}</code> : "null"}</p>
      </section>
    </div>
  );
};

export { Home };
