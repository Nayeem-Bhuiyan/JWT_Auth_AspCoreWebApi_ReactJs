using Microsoft.AspNetCore.Cryptography.KeyDerivation;
namespace NayeemWebApi.Services.AuthDataService.Interface
{
    public interface IPasswordHasherService
    {
        string GenerateIdentityV3Hash(string password, KeyDerivationPrf prf = KeyDerivationPrf.HMACSHA256, int iterationCount = 10000, int saltSize = 16);
        bool VerifyIdentityV3Hash(string password, string passwordHash);

        string HashPassword(string password);
        bool ValidatePassword(string password, string hashedPasswordFromDatabase);
    }
}
