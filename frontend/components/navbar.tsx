import { useLocation, useNavigate } from "react-router";

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

  const logout = async () => {
    try {
      const response = await fetch("http://localhost:8080/api/auth/logout", {
        method: "POST",
        credentials: "include",
        headers: {
          "Content-Type": "application/json",
        },
      });
      if (response.status === 200) {
        navigate("/login");
        console.log("logging out...");
      } else {
        throw new Error(
          "API request for message failed with status " + response.status,
        );
      }
    } catch (err) {
      console.error(err);
    }
  };

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
        onClick={() => logout()}
      >
        Logout
      </li>
    </ul>
  );
};

export { Navbar };
