const API_HOST = "http://127.0.0.1:8080";
const API_REGISTER_ENDPOINT = "/api/auth/register";
const API_LOGIN_ENDPOINT = "/api/auth/login";
const API_LOGOUT_ENDPOINT = "/api/auth/logout";
const API_USER_DETAILS_ENDPOINT = "/api/protected/me";
const JWT_TOKEN = "JWT-Token";

function GetFullUrl(endpoint: string): string {
  return API_HOST + endpoint;
}

export {
  GetFullUrl,
  API_REGISTER_ENDPOINT,
  API_LOGIN_ENDPOINT,
  API_LOGOUT_ENDPOINT,
  API_USER_DETAILS_ENDPOINT,
  JWT_TOKEN,
};
