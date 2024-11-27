using IssuerOfClaims.Services.Database;
using ServerUltilities.Identity;
using ServerUltilities;
using IssuerOfClaims.Models.DbModel;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using IssuerOfClaims.Extensions;

namespace IssuerOfClaims.Services.Token
{
    public class TokenService : ITokenService
    {
        private readonly ITokenResponseDbService _tokenResponseDbServices;

        public TokenService(ITokenResponseDbService tokenResponseDbServices, ITokenForRequestHandlerDbService tokenForRequestHandlerDbServices)
        {
            _tokenResponseDbServices = tokenResponseDbServices;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="tokenResponsePerRequest"></param>
        /// <param name="tokenType"></param>
        /// <param name="expiredTime">Only use for access token or refresh token</param>
        /// <returns></returns>
        /// <exception cref="InvalidOperationException"></exception>
        public TokenResponse CreateToken(string tokenType, DateTime? expiredTime = null, DateTime? issueAt = null)
        {
            string token = RNGCryptoServicesUltilities.RandomStringGeneratingWithLength(64);

            var tokenResponse = tokenType switch
            {
                OidcConstants.TokenTypes.AccessToken => _tokenResponseDbServices.CreateAccessToken(),
                OidcConstants.TokenTypes.RefreshToken => _tokenResponseDbServices.CreateRefreshToken(),
                OidcConstants.TokenTypes.IdentityToken => _tokenResponseDbServices.CreateIdToken(),
                _ => throw new InvalidOperationException($"{this.GetType().Name}: Something is wrong!")
            };

            tokenResponse.Token = tokenType switch
            {
                OidcConstants.TokenTypes.AccessToken => token,
                OidcConstants.TokenTypes.RefreshToken => token,
                OidcConstants.TokenTypes.IdentityToken => string.Empty,
                _ => throw new InvalidOperationException($"{this.GetType().Name}: Something is wrong!")
            };

            tokenResponse.TokenExpiried = tokenType switch
            {
                OidcConstants.TokenTypes.AccessToken => expiredTime == null ? DateTime.Now.AddHours(1) : expiredTime.Value,
                OidcConstants.TokenTypes.RefreshToken => expiredTime == null ? DateTime.Now.AddHours(4) : expiredTime.Value,
                OidcConstants.TokenTypes.IdentityToken => expiredTime == null ? DateTime.Now.AddHours(1) : expiredTime.Value,
                _ => throw new InvalidOperationException($"{this.GetType().Name}: Something is wrong!")
            };

            tokenResponse.IssueAt = issueAt == null ? DateTime.Now : issueAt;
            _tokenResponseDbServices.Update(tokenResponse);

            return tokenResponse;
        }


        // TODO: https://openid.net/specs/openid-connect-core-1_0.html#TokenResponse
        //     : following 3.1.3.3.  Successful Token Response
        //     : ID Token value associated with the authenticated session.
        private async Task<TokenResponse> ACF_CreateIdToken(IdentityRequestHandler currentRequestHandler, string clientId)
        {
            TokenResponse tokenResponse = CreateToken(OidcConstants.TokenTypes.IdentityToken);
            var idToken = await GenerateIdTokenAsync(currentRequestHandler.User, currentRequestHandler.RequestSession.Scope, currentRequestHandler.RequestSession.Nonce, clientId);
            tokenResponse.Token = idToken;

            _tokenResponseDbServices.Update(tokenResponse);

            return tokenResponse;
        }

        public async Task<TokenResponse> FindRefreshTokenAsync(string refreshToken)
        {
            return await _tokenResponseDbServices.FindAsync(refreshToken, OidcConstants.TokenTypes.RefreshToken);
        }

        public RSAParameters GetPublicKeyJson()
        {
            return RSAEncryptUtilities.ReadJsonKey(); // Public key
        }

        public bool Delete(TokenResponse tokenResponse)
        {
            return _tokenResponseDbServices.Delete(tokenResponse);
        }

        #region Generate Id token
        /// <summary>
        /// <para> TODO: Need to use Cast from CastObjectExtensions with 
        /// new { IdToken = string.Empty, PublicKey = new object() } as parameter
        /// to get explicit type of this function's result </para>
        /// <para> more info: https://openid.net/specs/openid-connect-core-1_0.html 3.1.3.7.  ID Token Validation</para>
        /// </summary>
        /// <param name="user"></param>
        /// <param name="scope"></param>
        /// <param name="nonce"></param>
        /// <param name="clientId"></param>
        /// <param name="authTime">for issue access token using offline-access with refresh token</param>
        /// <returns>key is token, value is public key</returns>
        public async Task<string> GenerateIdTokenAsync(UserIdentity user, string scope, string nonce, string clientId, string authTime = "")
        {
            try
            {
                // TODO: use rsa256 instead of hs256 for now
                var claims = await Task.Run(() => CreateClaimsForIdToken(user, nonce, authTime, scope, clientId));

                var allKeys = await Task.Run(() => RSAEncryptUtilities.CreateRsaPublicKeyAndPrivateKey());

                // TODO: will add rsa key to database

                // TODO: replace ClaimIDentity by JwtClaim
                var tokenDescriptor = new SecurityTokenDescriptor
                {
                    IssuedAt = DateTime.Now,
                    // TODO: idtoken will be used in short time
                    Expires = DateTime.Now.AddMinutes(15),
                    SigningCredentials = new SigningCredentials(new RsaSecurityKey(allKeys.PrivateKey), SecurityAlgorithms.RsaSha256),
                    Claims = claims,
                };

                var tokenHandler = new JwtSecurityTokenHandler();
                var token = tokenHandler.CreateToken(tokenDescriptor);
                var jwt = tokenHandler.WriteToken(token);

                return jwt;
            }
            catch (Exception ex)
            {
                throw new Exception(ex.Message);
            }
        }

        private static IDictionary<string, object> CreateClaimsForIdToken(UserIdentity user, string nonce, string authTime, string scope, string clientId)
        {
            var claims = new List<Claim>();
            var scopeVariables = scope.Split(" ").Select(s => s.ToLower());

            // TODO: will add more
            if (scopeVariables.Contains(IdentityServerConstants.StandardScopes.OpenId))
            {
                claims.Add(new Claim(JwtClaimTypes.Subject, user.UserName));
                claims.Add(new Claim(JwtClaimTypes.Audience, clientId));
                // TODO: hard code for now
                //claims.Add(new Claim(JwtClaimTypes.Issuer, System.Uri.EscapeDataString("https://localhost:7180")));
                claims.Add(new Claim(JwtClaimTypes.Issuer, "https://localhost:7180"));
                claims.Add(new Claim(JwtClaimTypes.AuthorizedParty, "https://localhost:7180"));
            }
            if (!string.IsNullOrEmpty(authTime))
                claims.Add(new Claim(JwtClaimTypes.AuthenticationTime, authTime));
            if (scopeVariables.Contains(IdentityServerConstants.StandardScopes.Profile))
            {
                claims.Add(new Claim(JwtClaimTypes.Name, user.FullName));
                claims.Add(new Claim(JwtClaimTypes.Gender, user.Gender));
                claims.Add(new Claim(JwtClaimTypes.UpdatedAt, user.UpdateTime.ToString()));
                claims.Add(new Claim(JwtClaimTypes.Picture, user.Avatar));
                claims.Add(new Claim(JwtClaimTypes.BirthDate, user.DateOfBirth.ToString()));
            }
            if (scopeVariables.Contains(IdentityServerConstants.StandardScopes.Email))
            {
                claims.Add(new Claim(JwtClaimTypes.Email, user.Email));
                claims.Add(new Claim(JwtClaimTypes.EmailVerified, user.EmailConfirmed.ToString()));
            }
            if (scopeVariables.Contains(IdentityServerConstants.StandardScopes.Phone))
            {
                claims.Add(new Claim(JwtClaimTypes.PhoneNumber, user.PhoneNumber));
                claims.Add(new Claim(JwtClaimTypes.PhoneNumberVerified, user.PhoneNumberConfirmed.ToString()));
            }
            // TODO: will check again
            if (scopeVariables.Contains(IdentityServerConstants.StandardScopes.Address))
            {
                //claims.Add(new Claim(JwtClaimTypes.Address, user.AddressFormatted));
                claims.Add(new Claim(JwtClaimTypes.Address, user.Address));
                claims.Add(new Claim(JwtClaimTypes.Locale, user.Locality));
            }
            // TOOD: will add later
            if (scopeVariables.Contains(Constants.CustomScope.Role))
            {
                user.IdentityUserRoles.ToList().ForEach(p =>
                {
                    claims.Add(new Claim(JwtClaimTypes.Role, p.Role.RoleName));
                });
            }
            if (!string.IsNullOrEmpty(nonce))
                claims.Add(new Claim(JwtRegisteredClaimNames.Nonce, nonce));

            return claims.Select(c => new KeyValuePair<string, object>(c.Type, c.Value)).ToDictionary();
        }
        #endregion
    }

    public interface ITokenService
    {
        TokenResponse CreateToken(string tokenType, DateTime? expiredTime = null, DateTime? issueAt = null);
        Task<string> GenerateIdTokenAsync(UserIdentity user, string scope, string nonce, string clientId, string authTime = "");
        Task<TokenResponse> FindRefreshTokenAsync(string refreshToken);
        RSAParameters GetPublicKeyJson();
        bool Delete(TokenResponse tokenResponse);
    }
}
