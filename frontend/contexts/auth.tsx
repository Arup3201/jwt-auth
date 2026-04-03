import { createContext, useCallback, useContext, useEffect } from "react";
import { useNavigate } from "react-router";
import { API_ROOT, ApiFetch, getValidToken } from "../utils/api";
import { tokenStore } from "../utils/token";

interface RegisterParams {
  email: string;
  name: string;
  password: string;
}

interface LoginParams {
  email: string;
  password: string;
}

interface AuthContextValue {
  register(p: RegisterParams): Promise<void>;
  login(p: LoginParams): Promise<void>;
  logout(): Promise<void>;
}

interface AuthProviderInterface {
  children: React.ReactNode;
}

const authContext = createContext<AuthContextValue>({
  register: (_p: RegisterParams) => Promise.resolve(),
  login: (_p: LoginParams) => Promise.resolve(),
  logout: () => Promise.resolve(),
});

const AuthProvider: React.FC<AuthProviderInterface> = ({ children }) => {
  const navigate = useNavigate();

  const register = useCallback(
    async ({ email, name, password }: RegisterParams) => {
      const res = await fetch(API_ROOT + "/auth/register", {
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
        throw new Error("User registration failed.");
      }
    },
    [],
  );

  const login = useCallback(async ({ email, password }: LoginParams) => {
    const res = await fetch(API_ROOT + "/auth/login", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      credentials: "include", // for refresh token cookie
      body: JSON.stringify({
        email: email,
        password: password,
      }),
    });
    if (!res.ok) throw new Error("Login failed");

    const data = await res.json();
    tokenStore.set(data.access_token);

    navigate("/");
  }, []);

  const logout = useCallback(async () => {
    const response = await ApiFetch("/auth/logout", {
      method: "POST",
      credentials: "include",
    });
    if (response.status === 200) {
      console.log("logging out...");
    } else {
      console.error("Something went wrong during logout.");
    }
    navigate("/login");
  }, []);

  useEffect(() => {
    window.addEventListener("auth:logout", logout);
    return () => window.removeEventListener("auth:logout", logout);
  }, [logout]);

  async function refreshToken() {
    try {
      await getValidToken();
    } catch (err) {
      console.error(err);
      navigate("/login");
    }
  }

  useEffect(() => {
    const token = tokenStore.get();
    if (token === null) {
      refreshToken();
    }
  }, []);

  return (
    <authContext.Provider
      value={{
        register,
        login,
        logout,
      }}
    >
      {children}
    </authContext.Provider>
  );
};

const useAuth = () => useContext(authContext);

export { useAuth, AuthProvider };
