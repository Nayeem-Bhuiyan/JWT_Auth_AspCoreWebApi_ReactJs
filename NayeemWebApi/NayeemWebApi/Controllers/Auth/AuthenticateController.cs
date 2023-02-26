using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using NayeemWebApi.Helper;
using NayeemWebApi.ProjectDto.Entity.UserEntity;
using NayeemWebApi.Services.AuthDataService.Interface;
using NayeemWebApi.Services.TokenDataService.Interface;
using NayeemWebApi.ViewModel.Auth;
using NayeemWebApi.ViewModel.Response;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
namespace NayeemWebApi.Controllers.Auth
{
    [Route("api/[controller]")]
    [ApiController]

    public class AuthenticateController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<ApplicationRole> _roleManager;
        private readonly IConfiguration _configuration;
        private readonly ITokenService _tokenService;
        private readonly IPasswordHasherService _passwordHasher;
        private readonly IAuthService _authService;
        public AuthenticateController(
            UserManager<ApplicationUser> userManager,
            RoleManager<ApplicationRole> roleManager,
            IConfiguration configuration,
            ITokenService tokenService,
            IPasswordHasherService passwordHasher,
            IAuthService authService
         )
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
            _tokenService = tokenService;
            _passwordHasher = passwordHasher;
            _authService = authService;
        }

        [HttpPost]
        [Route("login")]
        public async Task<IActionResult> Login([FromBody] LoginModel model)
        {
            var currentUser = await _userManager.FindByNameAsync(model.Username);

            #region ValidatePassword
            bool isValidPassword = _passwordHasher.VerifyIdentityV3Hash(model.Password, currentUser.PasswordHash);
            //bool isValidPassword = _passwordHasher.VerifyHashedPassword(model.Password, currentUser.PasswordHash);
            //bool isValidPassword = SecretHasher.VerifyPassword(model.Password, currentUser.PasswordHash);
            #endregion


            if (currentUser == null || !isValidPassword) return Unauthorized();
    
                var userRoles = await _userManager.GetRolesAsync(currentUser);

                var authClaims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, currentUser.UserName),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                };

                foreach (var userRole in userRoles)
                {
                    authClaims.Add(new Claim(ClaimTypes.Role, userRole));
                }
               
                var token =_tokenService.GenerateAccessToken(authClaims);
                var refreshToken =_tokenService.GenerateRefreshToken();

                _ = int.TryParse(_configuration["JWT:RefreshTokenValidityInDays"], out int refreshTokenValidityInDays);
                DateTime tokenValidTo = DateTime.Now.AddDays(refreshTokenValidityInDays);
            currentUser.RefreshToken = refreshToken;
            currentUser.RefreshTokenExpiryTime =tokenValidTo;
            await _userManager.UpdateAsync(currentUser);
            user _user = new user
            {
                accessToken = token,
                refreshToken = refreshToken,
                expiration = tokenValidTo,
                roles=userRoles,
                userName = currentUser?.UserName,
                email = currentUser?.Email,
            };
           return Ok(_user);
        }

        [HttpPost]
        [Route("register")]
        public async Task<IActionResult> Register(RegisterModel model)
        {
            var userExists = await _userManager.FindByNameAsync(model.Username);
            if (userExists != null)
                return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "User already exists!" });

            ApplicationUser user = new()
            {
                Email = model.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = model.Username,
                NormalizedUserName = model.Username.ToUpper().ToString()
            };

            #region GenerateHashPassword
            user.PasswordHash =_passwordHasher.GenerateIdentityV3Hash(model.Password);
            //user.PasswordHash= SecretHasher.GenerateHashPassword(model.Password);
            #endregion

            var result = _authService.AddUser(user);
            if (!result)
            {
                return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "User creation failed! Please check user details and try again." });
            }
            else
            {
                //if (!await _roleManager.RoleExistsAsync("User"))
                //{
                //    await _roleManager.CreateAsync(new IdentityRole("User"));
                //}
                await _userManager.AddToRoleAsync(user, UserRoles.User);
            }
            return Ok(new Response { Status = "Success", Message = "User created successfully!" });
        }

        [HttpPost]
        [Route("register-admin")]
        public async Task<IActionResult> RegisterAdmin([FromBody] RegisterModel model)
        {
            var userExists = await _userManager.FindByNameAsync(model.Username);
            if (userExists != null)
                return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "User already exists!" });

            ApplicationUser user = new()
            {
                Email = model.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = model.Username
            };
            var result = await _userManager.CreateAsync(user, model.Password);
            if (!result.Succeeded)
                return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "User creation failed! Please check user details and try again." });

            //if (!await _roleManager.RoleExistsAsync("Admin"))
            //    await _roleManager.CreateAsync(new IdentityRole(""));
            //if (!await _roleManager.RoleExistsAsync(UserRoles.User))
            //    await _roleManager.CreateAsync(new IdentityRole(UserRoles.User));

            if (await _roleManager.RoleExistsAsync(UserRoles.Admin))
            {
                await _userManager.AddToRoleAsync(user, UserRoles.Admin);
            }
            if (await _roleManager.RoleExistsAsync(UserRoles.Admin))
            {
                await _userManager.AddToRoleAsync(user, UserRoles.User);
            }
            return Ok(new Response { Status = "Success", Message = "User created successfully!" });
        }

        [HttpPost]
        [Route("refresh-token")]
        public async Task<IActionResult> RefreshToken(TokenModel tokenModel)
        {
            if (tokenModel is null)
            {
                return BadRequest("Invalid client request");
            }

            string? accessToken = tokenModel.AccessToken;
            string? refreshToken = tokenModel.RefreshToken;

            var principal =_tokenService.GetPrincipalFromExpiredToken(accessToken);
            if (principal == null)
            {
                return BadRequest("Invalid access token or refresh token");
            }

#pragma warning disable CS8600 // Converting null literal or possible null value to non-nullable type.
#pragma warning disable CS8602 // Dereference of a possibly null reference.
            string username = principal.Identity.Name;
#pragma warning restore CS8602 // Dereference of a possibly null reference.
#pragma warning restore CS8600 // Converting null literal or possible null value to non-nullable type.

            var user = await _userManager.FindByNameAsync(username);

            if (user == null || user.RefreshToken != refreshToken || user.RefreshTokenExpiryTime <= DateTime.Now)
            {
                return BadRequest("Invalid access token or refresh token");
            }

            var newAccessToken =_tokenService.GenerateAccessToken(principal.Claims.ToList());
            var newRefreshToken = _tokenService.GenerateRefreshToken();

            user.RefreshToken = newRefreshToken;
            await _userManager.UpdateAsync(user);

            return new ObjectResult(new
            {
                accessToken =newAccessToken,
                refreshToken = newRefreshToken
            });





            //var principal = _tokenService.GetPrincipalFromExpiredToken(accessToken);
            //var username = principal.Identity.Name; //this is mapped to the Name claim by default

            //var user = _usersDb.Users.SingleOrDefault(u => u.Username == username);
            //if (user == null || user.RefreshToken != refreshToken) return BadRequest();

            //var newJwtToken = _tokenService.GenerateAccessToken(principal.Claims);
            //var newRefreshToken = _tokenService.GenerateRefreshToken();

            //user.RefreshToken = newRefreshToken;
            //await _usersDb.SaveChangesAsync();

            //return new ObjectResult(new
            //{
            //    token = newJwtToken,
            //    refreshToken = newRefreshToken
            //});
        }

        [Authorize]
        [HttpPost]
        [Route("revoke/{username}")]
        public async Task<IActionResult> Revoke(string username)
        {
            var user = await _userManager.FindByNameAsync(username);
            if (user == null) return BadRequest("Invalid user name");

            user.RefreshToken = null;
            await _userManager.UpdateAsync(user);

            return NoContent();
        }

        [Authorize]
        [HttpPost]
        [Route("revoke-all")]
        public async Task<IActionResult> RevokeAll()
        {
            var users = _userManager.Users.ToList();
            foreach (var user in users)
            {
                user.RefreshToken = null;
                await _userManager.UpdateAsync(user);
            }

            return NoContent();
        }
    }
}
