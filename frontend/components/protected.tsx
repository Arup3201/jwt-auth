import { Outlet } from "react-router";
import { Navbar } from "./navbar";

const Protected = () => {
  return (
    <>
      <Navbar />
      <Outlet />
    </>
  );
};

export { Protected };
