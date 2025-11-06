import { useState, useEffect } from "react";
import { useNavigate } from "react-router"
import { useAuth } from "../hooks/useAuth";

const validateEmail = (email: string) => {
    return String(email)
        .toLowerCase()
        .match(
            /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|.(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/
        );
};

const Login = () => {
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [error, setError] = useState('');
    const { login, user } = useAuth();
    const navigate = useNavigate();


    useEffect(() => {
        if (user) navigate('/dashboard');
    }, [user]);


    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        setError('');

        if (email === "") {
            setError("Missing email")
            return
        }
        if (password === "") {
            setError("Missing password")
            return
        }
        if (!validateEmail(email)) {
            setError("Invalid email address. Example: john@example.com")
            return
        }

        try {
            await login(email, password);
        } catch (err) {
            if (err instanceof Error) {
                setError(err.message);
            }
        }
    };


    return (
        <div className="flex flex-col items-center mt-10">
            <h2 className="text-xl mb-4">Login</h2>
            <form onSubmit={handleSubmit} className="flex flex-col gap-2 w-64">
                <input
                    className="border p-2 rounded"
                    placeholder="Email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                />
                <input
                    className="border p-2 rounded"
                    placeholder="Password"
                    type="password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                />
                {error && <p className="text-red-500 text-sm">{error}</p>}
                <button type="submit" className="bg-blue-500 text-white p-2 rounded">Login</button>
            </form>
        </div>
    );
};

export { Login }