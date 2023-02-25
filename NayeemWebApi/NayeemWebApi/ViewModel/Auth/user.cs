using NayeemWebApi.ProjectDto.Entity.UserEntity;

namespace NayeemWebApi.ViewModel.Auth
{
    public class user
    {
        public string userName { get; set; }
        public string email { get; set; }
        public IList<string> roles { get; set; }
        public string accessToken { get; set; }
        public string refreshToken { get; set; }
        public DateTime? expiration { get; set; }
        

    }
}
