import { tokenStore } from "./token";

const API_ROOT = "http://localhost:8080/api";

const ApiFetch = async (
  url: string,
  initOptions?: RequestInit,
): Promise<Response> => {
  const accessToken = tokenStore.get();

  let options: RequestInit = {
    method: "GET",
    headers: {
      "Content-Type": "application/json",
      ...(accessToken ? { Authorization: "Bearer " + accessToken } : {}),
    },
  };

  if (initOptions) {
    options = {
      ...options,
      ...initOptions,
    };
  }

  const res = await fetch(API_ROOT + url, options);
  if (res.status === 401) {
    try {
      const newToken = await getValidToken();
      const res = await fetch(API_ROOT + url, {
        ...options,
        headers: {
          ...options.headers,
          Authorization: "Bearer " + newToken,
        },
      });
      if (!res.ok) throw new Error("Session refresh failed.");

      return res;
    } catch (err) {
      window.dispatchEvent(new Event("auth:logout"));
      throw new Error("Session expired. Try to login again.");
    }
  }

  return res;
};

// Lock for keeping only one refresh call active!
let refreshingPromise: null | Promise<Response>;

async function getValidToken() {
  if (refreshingPromise) {
    return refreshingPromise;
  }

  refreshingPromise = fetch(API_ROOT + "/auth/refresh", {
    method: "POST",
    credentials: "include",
  })
    .then(async (res) => {
      if (!res.ok) throw new Error("refresh token failed");
      const { access_token } = await res.json();
      tokenStore.set(access_token);
      return access_token;
    })
    .finally(() => (refreshingPromise = null));

  return refreshingPromise;
}

export { API_ROOT, ApiFetch, getValidToken };
