import { useState, useEffect, useContext, createContext } from 'react'
import { API_LOGIN_ENDPOINT, API_LOGOUT_ENDPOINT, API_USER_DETAILS_ENDPOINT, GetFullUrl } from '../constants/api'

interface User {
    id: string
    name: string
    email: string
}

interface AuthContextInterface {
    user: null | User,
    loading: boolean
    login: (email: string, password: string) => void,
    logout: () => void
}

const AuthContext = createContext<AuthContextInterface>(
    {
        user: null,
        loading: true,
        login: () => { },
        logout: () => { }
    }
);

const useAuth = () => useContext(AuthContext);

const AuthProvider = ({ children }: {
    children: React.ReactNode
}) => {
    const [user, setUser] = useState(null);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        const token = localStorage.getItem("jwtToken")
        if (!token) {
            console.error('Authorization token missing');
            return
        }

        // Check if user is logged in on mount
        fetch(GetFullUrl(API_USER_DETAILS_ENDPOINT), {
            credentials: 'include', headers: {
                "Authorization": "Bearer " + token
            }
        })
            .then(res => res.ok ? res.json() : null)
            .then(data => setUser(data?.user || null))
            .catch(() => setUser(null))
            .finally(() => setLoading(false));
    }, []);

    const login = async (username: string, password: string) => {
        const res = await fetch(GetFullUrl(API_LOGIN_ENDPOINT), {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password }),
            credentials: 'include'
        });
        if (res.ok) {
            const data = await res.json();
            setUser(data.user);
        } else {
            throw new Error('Invalid credentials');
        }
    };

    const logout = async () => {
        await fetch(GetFullUrl(API_LOGOUT_ENDPOINT), { method: 'POST', credentials: 'include' });
        setUser(null);
    };


    return (
        <AuthContext.Provider value={
            { user, login, logout, loading }
        }>
            {children}
        </AuthContext.Provider>
    );
};

export { useAuth, AuthProvider }