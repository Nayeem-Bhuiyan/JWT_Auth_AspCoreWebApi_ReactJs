import http from "../common.service/http.common";
import TokenService from "../common.service/token.service";

const register = (username, email, password) => {
  return http.post("/Authenticate/register", {
    username,
    email,
    password
  });
};

const login = (username, password) => {
  return http
    .post("/Authenticate/login", {
      username,
      password
    })
    .then((response) => {
      if (response.data.accessToken) {
        TokenService.setUser(response.data);
      }

      return response.data;
    });
};

const logout = () => {
  TokenService.removeUser();
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
