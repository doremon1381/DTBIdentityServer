using Microsoft.IdentityModel.Tokens;
using IssuerOfClaims.Models.DbModel;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace IssuerOfClaims.Models
{
    public static class Token
    {
        public static string CreateAccessToken(
            JwtSettings jwtOptions,
            string username,
            TimeSpan expiration,
            IdentityUserRole[] permissions)
        {
            var keyBytes = Encoding.UTF8.GetBytes(jwtOptions.Key);
            var symmetricKey = new SymmetricSecurityKey(keyBytes);

            var signingCredentials = new SigningCredentials(
                symmetricKey,
                // 👇 one of the most popular. 
                SecurityAlgorithms.HmacSha256);

            var claims = new List<Claim>()
            {
                new Claim("sub", username),
                new Claim("name", username),
                new Claim("aud", jwtOptions.Audience)
            };

            var roleClaims = permissions.Select(x => new Claim("role", x.Role.Name));
            claims.AddRange(roleClaims);

            var token = new JwtSecurityToken(
                issuer: jwtOptions.Issuer,
                audience: jwtOptions.Audience,
                claims: claims,
                expires: DateTime.Now.Add(expiration),
                signingCredentials: signingCredentials);

            var rawToken = new JwtSecurityTokenHandler().WriteToken(token);
            return rawToken;
        }

    }
}
