using Microsoft.AspNetCore.Identity;

namespace NayeemWebApi.ProjectDto.Entity.UserEntity
{
    public class ApplicationUser : IdentityUser
    {
        public string? RefreshToken { get; set; }
        public DateTime RefreshTokenExpiryTime { get; set; }
    }
}
