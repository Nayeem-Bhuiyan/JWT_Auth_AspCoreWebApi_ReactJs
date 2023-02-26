using NayeemWebApi.ProjectDto;
using NayeemWebApi.ProjectDto.Entity.UserEntity;
using NayeemWebApi.Services.AuthDataService.Interface;

namespace NayeemWebApi.Services.AuthDataService
{
    public class AuthService: IAuthService
    {
        private readonly ApplicationDbContext _applicationDbContext;
        public AuthService(ApplicationDbContext applicationDbContext)
        {
            _applicationDbContext=applicationDbContext;
        }


        public bool AddUser(ApplicationUser applicationUser)
        {
            try
            {
                _applicationDbContext.Add(applicationUser);
                _applicationDbContext.SaveChanges();
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                return true;
            }
           
        }

    }
}
