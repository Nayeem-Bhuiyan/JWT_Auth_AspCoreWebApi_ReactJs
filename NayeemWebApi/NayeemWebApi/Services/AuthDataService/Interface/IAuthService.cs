using NayeemWebApi.ProjectDto.Entity.UserEntity;

namespace NayeemWebApi.Services.AuthDataService.Interface
{
    public interface IAuthService
    {
        bool AddUser(ApplicationUser applicationUser);
    }
}
