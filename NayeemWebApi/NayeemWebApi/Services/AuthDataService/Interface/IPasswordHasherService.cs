using Microsoft.AspNetCore.Cryptography.KeyDerivation;
namespace NayeemWebApi.Services.AuthDataService.Interface
{
    public interface IPasswordHasherService
    {
        string GenerateIdentityV3Hash(string inputTextPassword, KeyDerivationPrf prf = KeyDerivationPrf.HMACSHA256, int iterationCount = 10000, int saltSize = 16);
        bool VerifyIdentityV3Hash(string inputTextPassword, string dbHashPassword);

        string GenerateHashPassword(string inputTextPassword);
        bool VerifyHashedPassword(string inputTextPassword, string dbHashPassword);
    }
}
