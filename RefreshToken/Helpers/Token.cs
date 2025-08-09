using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace RefreshToken.Helpers
{
    public class Token
    {
        private static string secretKey ="lkmks123456ghjkl;ertyuiovbnm$bnmpoueuueyhhhhsjiwjdw[]dertyuiopebb";
        private static Dictionary<string, string> refreshTokens = new();

        public static string GenerateToken(int userID, string userName, string role)
        {
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey));

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new System.Security.Claims.ClaimsIdentity(new[]
                {
                    new Claim(ClaimTypes.NameIdentifier, userID.ToString()),
                    new Claim(ClaimTypes.Name, userName),
                    new Claim(ClaimTypes.Role,role)
                }),
                Issuer = "issuer",
                Audience = "audience",
                SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256),
                Expires = DateTime.UtcNow.AddMinutes(1),

            };

            var tokenHandler = new JwtSecurityTokenHandler();

            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }

        public static string GenerateRefreshToken()
        {
            var randomNum = new byte[32];
            var rng = RandomNumberGenerator.Create();

            rng.GetBytes(randomNum);
            return Convert.ToBase64String(randomNum);

        }

        public static ClaimsPrincipal GetPrincipalFromExpiredToken(string token)
        {
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey));

            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = false,
                ValidateIssuerSigningKey = true,
                ValidIssuer = "issuer",
                ValidAudience = "audience",
                IssuerSigningKey = key
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            SecurityToken securityToken;

            var principal = tokenHandler.ValidateToken(token,tokenValidationParameters, out securityToken);

            var jwtSecurityToken = securityToken as JwtSecurityToken;
            if (jwtSecurityToken == null || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
                throw new SecurityTokenException("Invalid token");

            return principal;

        }

        public static void SaveRefreshToken(string userName, string refreshToken)
        {
            refreshTokens[userName] = refreshToken;
        }

        public static bool ValidateRefreshToken(string userName, string refreshToken)
        {
            return refreshTokens.ContainsKey(userName) && refreshTokens[userName] == refreshToken;
        }
    }
}
