import { useLocation, useNavigate } from "react-router";
import { useAuth } from "../contexts/auth";

const NAVS = [
  {
    id: "home",
    name: "Home",
    link: "/",
  },
];

const Navbar = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const { logout } = useAuth();

  return (
    <ul className="flex gap-4 bg-blue-50 justify-center p-2 mx-auto">
      {NAVS.map((n) => {
        let cls = "p-2 rounded text-gray-700";
        if (location.pathname === n.link) {
          cls += " bg-blue-100";
        } else {
          cls += " cursor-pointer hover:text-gray-900 hover:underline";
        }

        return (
          <li
            key={n.id}
            className={cls}
            onClick={() => location.pathname !== n.link && navigate(n.link)}
          >
            {n.name}
          </li>
        );
      })}
      <li
        className="p-2 rounded text-gray-700 cursor-pointer bg-blue-100 ml-auto"
        onClick={async () => await logout()}
      >
        Logout
      </li>
    </ul>
  );
};

export { Navbar };
