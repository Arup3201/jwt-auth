import { useNavigate, Link } from "react-router";
import { useAuth } from "../hooks/useAuth";

const Navbar = () => {
    const { user, logout } = useAuth();
    const navigate = useNavigate();


    const handleLogout = async () => {
        await logout();
        navigate('/');
    };


    return (
        <nav className="flex justify-between bg-gray-200 p-4">
            <div className="flex gap-4">
                <Link to="/">Home</Link>
                <Link to="/about">About</Link>
                <Link to="/dashboard">Dashboard</Link>
                <Link to="/settings">Settings</Link>
            </div>
            <div>
                {user ? (
                    <>
                        <span className="mr-4">Hello, {user.name}</span>
                        <button onClick={handleLogout} className="bg-red-500 text-white px-3 py-1 rounded">Logout</button>
                    </>
                ) : (
                    <Link to="/login" className="bg-blue-500 text-white px-3 py-1 rounded">Login</Link>
                )}
            </div>
        </nav>
    );
};

export { Navbar }