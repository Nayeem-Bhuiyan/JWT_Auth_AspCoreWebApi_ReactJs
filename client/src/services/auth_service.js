import http from "../http_common";

const API_URL = "/Authenticate/";

const register = (username, email, password) => {
  return http.post(API_URL + "register", {
    username,
    email,
    password,
  });
};

const login = (username, password) => {
  return http
    .post(API_URL + "login", {
      username,
      password,
    })
    .then((response) => {
      console.log(response);
      if (response.data.accessToken) {
        localStorage.setItem("user", JSON.stringify(response.data.user));
        localStorage.setItem("accessToken", JSON.stringify(response.data.accessToken));
      }

      return response.data;
    });
};

const logout = () => {
  localStorage.removeItem("user");
  localStorage.removeItem("accessToken");
};

const getCurrentUser = () => {
  return JSON.parse(localStorage.getItem("user"));
};

const AuthService = {
  register,
  login,
  logout,
  getCurrentUser,
};

export default AuthService;
