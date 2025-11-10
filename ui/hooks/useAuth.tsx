import { useNavigate } from "react-router";

import { useState, useEffect, useContext, createContext } from "react";
import {
  API_LOGIN_ENDPOINT,
  API_LOGOUT_ENDPOINT,
  API_USER_DETAILS_ENDPOINT,
  JWT_TOKEN,
  GetFullUrl,
} from "../constants/api";

interface User {
  username: string;
  fullName: string;
  street: string;
  city: string;
  state: string;
  postCode: string;
  company: string;
  designation: string;
}

type AsyncLogin = (email: string, password: string) => Promise<void>;
type AsyncLogout = () => Promise<void>;

interface AuthContextInterface {
  user: null | User;
  loading: boolean;
  login: AsyncLogin;
  logout: AsyncLogout;
}

const AuthContext = createContext<AuthContextInterface>({
  user: null,
  loading: true,
  login: async (_, __) => {},
  logout: async () => {},
});

const useAuth = () => useContext(AuthContext);

const AuthProvider = ({ children }: { children: React.ReactNode }) => {
  const navigate = useNavigate();
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const token = localStorage.getItem(JWT_TOKEN);
    if (!token) {
      console.error("Authorization token missing");
      return;
    }

    // Check if user is logged in on mount
    fetch(GetFullUrl(API_USER_DETAILS_ENDPOINT), {
      credentials: "include",
      headers: {
        Authorization: "Bearer " + token,
      },
    })
      .then((res) => (res.ok ? res.json() : null))
      .then((userData) => {
        setUser(() => {
          console.log(userData);
          if (userData.username != null) {
            return {
              username: userData["username"],
              fullName: userData["full_name"],
              street: userData["street"],
              city: userData["city"],
              state: userData["state"],
              postCode: userData["post_code"],
              designation: userData["designation"],
            } as User;
          } else {
            return null;
          }
        });
      })
      .catch(() => setUser(null))
      .finally(() => setLoading(false));
  }, []);

  const login = async (username: string, password: string) => {
    const res = await fetch(GetFullUrl(API_LOGIN_ENDPOINT), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
      credentials: "include",
    });
    if (res.ok) {
      const token = await res.json();
      console.log(token.access_token);
      localStorage.setItem(JWT_TOKEN, token.access_token);
      navigate("/dashboard");
    } else {
      throw new Error("Invalid credentials");
    }
  };

  const logout = async () => {
    try {
      await fetch(GetFullUrl(API_LOGOUT_ENDPOINT), {
        method: "POST",
        credentials: "include",
      });
      localStorage.removeItem(JWT_TOKEN);
      setUser(null);
      navigate("/login");
    } catch (err) {
      if (err instanceof Error) {
        console.error(err.message);
      }
    }
  };

  return (
    <AuthContext.Provider value={{ user, login, logout, loading }}>
      {children}
    </AuthContext.Provider>
  );
};

export { useAuth, AuthProvider };
