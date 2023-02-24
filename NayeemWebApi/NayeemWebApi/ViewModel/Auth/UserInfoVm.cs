using NayeemWebApi.ProjectDto.Entity.UserEntity;

namespace NayeemWebApi.ViewModel.Auth
{
    public class UserInfoVm
    {
        public IList<string> roles { get; set; }
        public string accessToken { get; set; }
        public string refreshToken { get; set; }
        public DateTime? expiration { get; set; }
        public ApplicationUser user { get; set; }
    }
}
