import { useEffect, useState } from "react";
import { useNavigate } from "react-router";

interface User {
  id: string;
  email: string;
  fullName: string;
  createdAt: string;
}

const Home = () => {
  const navigate = useNavigate();

  const [serverMessage, setServerMessage] = useState<string | null>(null);
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function getUserInfo() {
    setIsLoading(true);
    setError(null);

    try {
      const res = await fetch("http://localhost:8080/api/user-info", {
        method: "GET",
        credentials: "include",
        headers: {
          "Content-Type": "application/json",
        },
      });
      if (res.status === 200) {
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
      } else {
        throw new Error(
          "Failed to get user information with status " + res.status,
        );
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
        const response = await fetch("http://localhost:8080/api/message", {
          method: "GET",
          credentials: "include",
          headers: {
            "Content-Type": "application/json",
          },
        });
        if (response.status === 401) {
          console.error("User not logged in!");
          navigate("/login");
        } else if (response.status === 200) {
          const json = await response.json();
          if (json.message) {
            setServerMessage(json.message);
          } else {
            throw new Error("No message received");
          }
        } else {
          throw new Error(
            "API request for message failed with status " + response.status,
          );
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
