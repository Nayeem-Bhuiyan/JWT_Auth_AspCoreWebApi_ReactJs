export default function authHeader() {
    const accessToken = JSON.parse(localStorage.getItem('accessToken'));
  
    if (accessToken) {
      return { Authorization: 'Bearer ' + accessToken }; // for Spring Boot back-end
      // return { 'x-access-token': user.accessToken };       // for Node.js Express back-end
    } else {
      return {};
    }
  }