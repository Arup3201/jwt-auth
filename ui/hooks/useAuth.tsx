import { useState, useEffect, useContext, createContext } from 'react'

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
        // Check if user is logged in on mount
        fetch('/api/auth/me', { credentials: 'include' })
            .then(res => res.ok ? res.json() : null)
            .then(data => setUser(data?.user || null))
            .catch(() => setUser(null))
            .finally(() => setLoading(false));
    }, []);

    const login = async (email: string, password: string) => {
        const res = await fetch('/api/auth/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password }),
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
        await fetch('/api/auth/logout', { method: 'POST', credentials: 'include' });
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