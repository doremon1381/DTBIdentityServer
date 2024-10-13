using IssuerOfClaims.Services.Database;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using ServerDbModels;
using ServerUltilities;
using ServerUltilities.Identity;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using IssuerOfClaims.Extensions;

namespace IssuerOfClaims.Services.Token
{
    /// <summary>
    /// Issue id token, refresh token and access token
    /// </summary>
    public class TokenManager : ITokenManager
    {
        private readonly ITokenResponseDbServices _tokenResponseDbServices;
        private readonly ITokenResponsePerHandlerDbServices _tokensPerIdentityRequestDbServices;
        private readonly ITokenRequestSessionDbServices _tokenRequestSessionDbServices;
        private readonly ITokenRequestHandlerDbServices _tokenRequestHandlerDbServices;

        public TokenManager(ITokenResponseDbServices tokenResponseDbServices
            , ITokenResponsePerHandlerDbServices tokenResponsePerHandlerDbServices, ITokenRequestSessionDbServices tokenRequestSessionDbServices
            , ITokenRequestHandlerDbServices tokenRequestHandlerDbServices)
        {
            _tokenResponseDbServices = tokenResponseDbServices;
            _tokensPerIdentityRequestDbServices = tokenResponsePerHandlerDbServices;
            _tokenRequestSessionDbServices = tokenRequestSessionDbServices;

            _tokenRequestHandlerDbServices = tokenRequestHandlerDbServices;
        }

        // TODO: will check again
        public object IssueTokenForRefreshToken(TokenResponse previousRefreshResponse)
        {
            var lastestRefreshTokenBeUsed = previousRefreshResponse.TokenResponsePerHandler.Last();
            var tokenRequestHandler = _tokenRequestHandlerDbServices.FindById(lastestRefreshTokenBeUsed.TokenRequestHandlerId);

            // create new id token, remove the old, add the new into previous authenticate session
            // create new access token if it's expired, if access token is created new, remove the old, add the new one into previous authenticate session
            // create new refresh token if it's expired, if refresh token is created new, remove the old, add the new one into previous authenticate session

            var accessToken = UsingRefreshToken_IssuseToken(tokenRequestHandler, tokenRequestHandler.TokenResponsePerHandlers.First(t => t.TokenResponse.TokenType.Equals(TokenType.AccessToken)), TokenType.AccessToken);
            var refreshToken = UsingRefreshToken_IssuseToken(tokenRequestHandler, lastestRefreshTokenBeUsed, TokenType.RefreshToken);
            var idToken = UsingRefreshToken_IssuseIdToken(tokenRequestHandler, tokenRequestHandler.TokenResponsePerHandlers.First(t => t.TokenResponse.TokenType.Equals(TokenType.IdToken)), out object publicKey);

            var responseBody = CreateTokenResponseBody(accessToken.Token, idToken.Token, (accessToken.TokenExpiried - DateTime.Now).Value.TotalSeconds, publicKey, refreshToken.Token);

            return responseBody;
        }

        /// <summary>
        /// TODO: for now
        /// </summary>
        /// <param name="currentRequestHandler"></param>
        /// <returns></returns>
        private TokenResponse UsingRefreshToken_IssuseIdToken(TokenRequestHandler currentRequestHandler, TokenResponsePerIdentityRequest tokenResponsePerIdentityRequest, out object publicKey)
        {
            TokenResponse idToken = CreateToken(TokenType.IdToken);
            var composedObj = GenerateIdTokenAndRsaSha256PublicKey(currentRequestHandler.User, currentRequestHandler.TokenRequestSession.Scope, ""
                , currentRequestHandler.TokenRequestSession.Client.ClientId, currentRequestHandler.SuccessAt.Value.ToString())
                .Cast(new { IdToken = string.Empty, PublicKey = new object() });

            idToken.Token = composedObj.IdToken;
            publicKey = composedObj.PublicKey;

            _tokenResponseDbServices.Update(idToken);
            _tokenResponseDbServices.Delete(tokenResponsePerIdentityRequest.TokenResponse);

            CreateTokenResponsePerIdentityRequest(currentRequestHandler, idToken);

            return idToken;
        }

        private TokenResponse UsingRefreshToken_IssuseToken(TokenRequestHandler tokenRequestHandler, TokenResponsePerIdentityRequest tokenResponsePerIdentityRequest, string tokenType)
        {
            TokenResponse token = tokenResponsePerIdentityRequest.TokenResponse;

            if (token.TokenExpiried < DateTime.Now)
            {
                token = CreateToken(tokenType);

                _tokenResponseDbServices.Delete(tokenResponsePerIdentityRequest.TokenResponse);
                _tokensPerIdentityRequestDbServices.Delete(tokenResponsePerIdentityRequest);

                CreateTokenResponsePerIdentityRequest(tokenRequestHandler, token);
            }

            return token;
        }

        public object ACF_IssueToken(UserIdentity user, Client client, int currentRequestHandlerId)
        {
            var currentRequestHandler = _tokenRequestHandlerDbServices.FindById(currentRequestHandlerId);

            // TODO: use this temporary
            TokenResponse idToken = ACF_CreateIdToken(currentRequestHandler, client.ClientId, out object publicKey);

            bool isOfflineAccess = currentRequestHandler.TokenRequestSession.IsOfflineAccess;

            // I want to reuse token response if it is not expired
            var latestRefreshToken = _tokensPerIdentityRequestDbServices.FindLast(user.Id, client.Id, needAccessToken: false);
            var latestAccessToken = _tokensPerIdentityRequestDbServices.FindLast(user.Id, client.Id, needAccessToken: true);

            TokenResponse refreshToken = new TokenResponse();
            TokenResponse accessToken = new TokenResponse();
            double accessTokenExpiredTime = 3600;
            object responseBody = new object();

            // TODO: at this step, need to check offline_access is inside authrization login request is true or fault
            //     : if fault, then response will not include refresh token
            //     : if true, then add refresh token along with response
            if (isOfflineAccess)
            {
                // latest token response does not have refresh token
                if (latestRefreshToken == null
                    || latestRefreshToken.TokenResponse == null)
                {
                    refreshToken = CreateToken(TokenType.RefreshToken);

                    // latest access token can be used
                    // , by logic of creation token response, those two (access-refresh token) will go along as a pair
                    if (latestAccessToken != null && latestAccessToken.TokenResponse.TokenExpiried >= DateTime.Now)
                    {
                        accessToken = latestAccessToken.TokenResponse;
                        accessTokenExpiredTime = (latestAccessToken.TokenResponse.TokenExpiried - DateTime.Now).Value.TotalSeconds;
                    }
                    // latest access token can not be re-used, expired
                    else
                    {
                        // if expired, create new
                        accessToken = CreateToken(TokenType.AccessToken);
                    }
                }
                // latest token response has refresh token
                else if (latestRefreshToken != null && latestRefreshToken.TokenResponse != null)
                {
                    // access token and refresh token can be re-used 
                    if (latestAccessToken.TokenResponse.TokenExpiried >= DateTime.Now
                        && latestRefreshToken.TokenResponse.TokenExpiried >= DateTime.Now)
                    {
                        accessToken = latestAccessToken.TokenResponse;
                        refreshToken = latestRefreshToken.TokenResponse;

                        accessTokenExpiredTime = (accessToken.TokenExpiried - DateTime.Now).Value.TotalSeconds;
                    }
                    // refresh token can be re-used, but not access token
                    else if (latestAccessToken.TokenResponse.TokenExpiried < DateTime.Now
                            && latestRefreshToken.TokenResponse.TokenExpiried >= DateTime.Now)
                    {
                        // access token expired time may over the refresh token expired time
                        TimeSpan diff = (TimeSpan)(latestRefreshToken.TokenResponse.TokenExpiried - DateTime.Now);
                        var expiredTime = diff.TotalSeconds < 3600 ? DateTime.Now.AddSeconds(diff.TotalSeconds)
                            : DateTime.Now.AddHours(1);

                        accessToken = CreateToken(TokenType.AccessToken, expiredTime);
                        refreshToken = latestRefreshToken.TokenResponse;
                    }
                    // neither access token and refresh token cant be re-used
                    else if (latestAccessToken.TokenResponse.TokenExpiried < DateTime.Now
                        && latestRefreshToken.TokenResponse.TokenExpiried < DateTime.Now)
                    {
                        accessToken = CreateToken(TokenType.AccessToken);
                        refreshToken = CreateToken(TokenType.RefreshToken);
                    }
                    #region for test
                    //else if (latestAccessToken.TokenResponse.TokenExpiried > DateTime.Now
                    //    && latestRefreshToken.TokenResponse.TokenExpiried < DateTime.Now)
                    //{
                    //    //var tokenResponse = _tokenResponseDbServices.CreateAccessToken();
                    //    //currentRequestHandler.TokenResponse = tokenResponse;

                    //    //string access_token = RNGCryptoServicesUltilities.RandomStringGeneratingWithLength(64);
                    //    //string refresh_token = RNGCryptoServicesUltilities.RandomStringGeneratingWithLength(64);

                    //    //tokenResponse.AccessToken = access_token;
                    //    //tokenResponse.IdToken = id_token;
                    //    //tokenResponse.AccessTokenExpiried = DateTime.Now.AddHours(1);
                    //    //tokenResponse.RefreshToken = refresh_token;
                    //    //tokenResponse.RefreshTokenExpiried = DateTime.Now.AddHours(4);

                    //    //responseBody = CreateTokenResponseBody(access_token, id_token, 3600, refresh_token);
                    //}
                    #endregion
                }

                responseBody = CreateTokenResponseBody(accessToken.Token, idToken.Token, accessTokenExpiredTime, publicKey, refreshToken.Token);
            }
            else if (!isOfflineAccess)
            {
                // latest access token can be used
                if (latestAccessToken != null && latestAccessToken.TokenResponse.TokenExpiried >= DateTime.Now)
                {
                    accessToken = latestAccessToken.TokenResponse;
                }
                else
                {
                    // create new 
                    accessToken = CreateToken(TokenType.AccessToken);
                }

                responseBody = CreateTokenResponseBody(accessToken.Token, idToken.Token, accessTokenExpiredTime, publicKey);
            }

            CreateTokenResponsePerIdentityRequest(currentRequestHandler, accessToken);
            CreateTokenResponsePerIdentityRequest(currentRequestHandler, refreshToken);
            // TODO: will think about how to handle idtoken, create one for user, update when information of user is changed or sth else
            CreateTokenResponsePerIdentityRequest(currentRequestHandler, idToken);

            currentRequestHandler.TokenRequestSession.IsInLoginSession = false;
            _tokenRequestSessionDbServices.Update(currentRequestHandler.TokenRequestSession);

            return responseBody;
        }

        // TODO: https://openid.net/specs/openid-connect-core-1_0.html#TokenResponse
        //     : following 3.1.3.3.  Successful Token Response
        //     : ID Token value associated with the authenticated session.
        private TokenResponse ACF_CreateIdToken(TokenRequestHandler currentRequestHandler, string clientId, out object publicKey)
        {
            TokenResponse tokenResponse = CreateToken(TokenType.IdToken);
            var composedObj = GenerateIdTokenAndRsaSha256PublicKey(currentRequestHandler.User, currentRequestHandler.TokenRequestSession.Scope, currentRequestHandler.TokenRequestSession.Nonce, clientId)
                .Cast(new { IdToken = string.Empty, PublicKey = new object() });

            tokenResponse.Token = composedObj.IdToken;
            publicKey = composedObj.PublicKey;

            _tokenResponseDbServices.Update(tokenResponse);

            return tokenResponse;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="tokenResponsePerRequest"></param>
        /// <param name="tokenType"></param>
        /// <param name="manualDateTime">Only use for access token or refresh token</param>
        /// <returns></returns>
        /// <exception cref="InvalidOperationException"></exception>
        private TokenResponse CreateToken(string tokenType, DateTime? manualDateTime = null)
        {
            string token = RNGCryptoServicesUltilities.RandomStringGeneratingWithLength(64);

            var tokenResponse = tokenType switch
            {
                TokenType.AccessToken => _tokenResponseDbServices.CreateAccessToken(),
                TokenType.RefreshToken => _tokenResponseDbServices.CreateRefreshToken(),
                TokenType.IdToken => _tokenResponseDbServices.CreateIdToken(),
                _ => throw new InvalidOperationException($"{this.GetType().Name}: Something is wrong!")
            };

            tokenResponse.Token = tokenType switch
            {
                TokenType.AccessToken => token,
                TokenType.RefreshToken => token,
                TokenType.IdToken => string.Empty,
                _ => throw new InvalidOperationException($"{this.GetType().Name}: Something is wrong!")
            };

            tokenResponse.TokenExpiried = tokenType switch
            {
                TokenType.AccessToken => manualDateTime == null ? DateTime.Now.AddHours(1) : manualDateTime,
                TokenType.RefreshToken => manualDateTime == null ? DateTime.Now.AddHours(4) : manualDateTime,
                TokenType.IdToken => null,
                _ => throw new InvalidOperationException($"{this.GetType().Name}: Something is wrong!")
            };

            tokenResponse.IssueAt = DateTime.Now;
            _tokenResponseDbServices.Update(tokenResponse);

            return tokenResponse;
        }

        private void CreateTokenResponsePerIdentityRequest(TokenRequestHandler currentRequestHandler, TokenResponse tokenResponse)
        {
            TokenResponsePerIdentityRequest tokensPerIdentityRequest = _tokensPerIdentityRequestDbServices.GetDraftObject();
            tokensPerIdentityRequest.TokenResponse = tokenResponse;
            tokensPerIdentityRequest.TokenRequestHandler = currentRequestHandler;

            _tokensPerIdentityRequestDbServices.Update(tokensPerIdentityRequest);
        }

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
        public object GenerateIdTokenAndRsaSha256PublicKey(UserIdentity user, string scope, string nonce, string clientId, string authTime = "")
        {
            try
            {
                // TODO: use rsa256 instead of hs256 for now
                var claims = CreateClaimsForIdToken(user, nonce, authTime, scope, clientId);

                var publicPrivateKeys = CreateRsaPublicKeyAndPrivateKey();

                // TODO: will add rsa key to database

                // TODO: replace ClaimIDentity by JwtClaim
                var tokenDescriptor = new SecurityTokenDescriptor
                {
                    IssuedAt = DateTime.UtcNow,
                    // TODO: idtoken will be used in short time
                    Expires = DateTime.UtcNow.AddMinutes(15),
                    SigningCredentials = new SigningCredentials(new RsaSecurityKey(publicPrivateKeys.Key), SecurityAlgorithms.RsaSha256),
                    Claims = claims,
                };

                var tokenHandler = new JwtSecurityTokenHandler();
                var token = tokenHandler.CreateToken(tokenDescriptor);
                var jwt = tokenHandler.WriteToken(token);

                var jsonPublicKey = GetJsonPublicKey(publicPrivateKeys.Value);

                return new { IdToken = jwt, PublicKey = jsonPublicKey };
            }
            catch (Exception ex)
            {
                throw new Exception(ex.Message);
            }
        }

        private static IDictionary<string, object> CreateClaimsForIdToken(UserIdentity user, string nonce, string authTime, string scope, string clientId)
        {
            var claims = new List<Claim>();
            var scopeVariables = scope.Split(" ");

            if (scopeVariables.Contains(IdentityServerConstants.StandardScopes.OpenId))
            {
                claims.Add(new Claim(JwtClaimTypes.Subject, user.UserName));
                claims.Add(new Claim(JwtClaimTypes.Audience, clientId));
                //claims.Add(new Claim(JwtClaimTypes.IssuedAt, DateTime.Now.ToString()));
                // TODO: hard code for now
                claims.Add(new Claim(JwtClaimTypes.Issuer, System.Uri.EscapeDataString("https://localhost:7180")));
            }
            if (!string.IsNullOrEmpty(authTime))
                claims.Add(new Claim(JwtClaimTypes.AuthenticationTime, authTime));
            if (scopeVariables.Contains(IdentityServerConstants.StandardScopes.Profile))
            {
                // TODO: will add more
                claims.Add(new Claim(JwtClaimTypes.Name, user.FullName));
                //claims.Add(new Claim("username", user.UserName));
                claims.Add(new Claim(JwtClaimTypes.Gender, user.Gender));
                claims.Add(new Claim(JwtClaimTypes.UpdatedAt, user.UpdateTime.ToString()));
                claims.Add(new Claim(JwtClaimTypes.Picture, user.Avatar));
                claims.Add(new Claim(JwtClaimTypes.BirthDate, user.DateOfBirth.ToString()));
                //claims.Add(new Claim(JwtClaimTypes.Locale, user.lo))
            }
            if (scopeVariables.Contains(IdentityServerConstants.StandardScopes.Email))
            {
                claims.Add(new Claim(JwtClaimTypes.Email, user.Email));
                claims.Add(new Claim(JwtClaimTypes.EmailVerified, user.IsEmailConfirmed.ToString()));
            }
            if (scopeVariables.Contains(IdentityServerConstants.StandardScopes.Phone))
            {
                claims.Add(new Claim(JwtClaimTypes.PhoneNumber, user.PhoneNumber));
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

        #region Implement RsaSha256, powered by copilot
        /// <summary>
        /// for this pair, key is rsa private key, value is rsa public key
        /// </summary>
        /// <returns></returns>
        private static KeyValuePair<RSAParameters, RSAParameters> CreateRsaPublicKeyAndPrivateKey()
        {
            RSAParameters publicKey;
            RSAParameters privateKey;

            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                // Get the public and private key
                publicKey = rsa.ExportParameters(false); // Public key
                privateKey = rsa.ExportParameters(true); // Private key

                // Store or distribute these keys securely
            }

            return new KeyValuePair<RSAParameters, RSAParameters>(privateKey, publicKey);
        }

        private object GetJsonPublicKey(RSAParameters publicKey)
        {
            var jsonObj = JsonConvert.SerializeObject(publicKey);
            return jsonObj;
        }

        // Encrypt using recipient's public key
        private static byte[] Encrypt(byte[] data, RSAParameters publicKey)
        {
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                rsa.ImportParameters(publicKey);
                return rsa.Encrypt(data, true); // Use OAEP padding for security
            }
        }

        // Decrypt using recipient's private key
        private static byte[] Decrypt(byte[] encryptedData, RSAParameters privateKey)
        {
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                rsa.ImportParameters(privateKey);
                return rsa.Decrypt(encryptedData, true);
            }
        }

        // Sign data using SHA-256 and RSA
        private static byte[] SignData(byte[] data, RSAParameters privateKey)
        {
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                rsa.ImportParameters(privateKey);
                using (SHA256 sha256 = SHA256.Create())
                {
                    byte[] hash = sha256.ComputeHash(data);
                    return rsa.SignHash(hash, CryptoConfig.MapNameToOID(SecurityAlgorithms.Sha256));
                }
            }
        }

        // Verify signature
        private static bool VerifySignature(byte[] data, byte[] signature, RSAParameters publicKey)
        {
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                rsa.ImportParameters(publicKey);
                using (SHA256 sha256 = SHA256.Create())
                {
                    byte[] hash = sha256.ComputeHash(data);
                    return rsa.VerifyHash(hash, CryptoConfig.MapNameToOID(SecurityAlgorithms.Sha256), signature);
                }
            }
        }

        public static void VeriryJwtSignature(RSAParameters publicKey, string token)
        {
            var tokenHandler = new JwtSecurityTokenHandler();

            // Verify JWT signature
            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new RsaSecurityKey(publicKey),
                ValidateIssuer = false, // Customize as needed
                ValidateAudience = false, // Customize as needed
            };

            var claimsPrincipal = tokenHandler.ValidateToken(token, validationParameters, out _);
            // 'claimsPrincipal' contains the validated claims
        }
        #endregion

        private static object CreateTokenResponseBody(string access_token, string id_token, double expired_in, object publicKey, string refresh_token = "")
        {
            object responseBody;
            if (string.IsNullOrEmpty(refresh_token))
            {
                responseBody = new
                {
                    access_token = access_token,
                    id_token = id_token,
                    token_type = "Bearer",
                    public_key = publicKey,
                    // TODO: set by seconds
                    expires_in = expired_in
                };
            }
            else
                responseBody = new
                {
                    access_token = access_token,
                    id_token = id_token,
                    refresh_token = refresh_token,
                    token_type = "Bearer",
                    public_key = publicKey,
                    // TODO: set by seconds
                    expires_in = expired_in
                };

            return responseBody;
        }

        public TokenRequestSession CreateTokenRequestSession()
        {
            return _tokenRequestSessionDbServices.CreateTokenRequestSession();
        }

        public TokenRequestHandler GetDraftTokenRequestHandler()
        {
            return _tokenRequestHandlerDbServices.GetDraftObject();
        }

        public bool UpdateTokenRequestHandler(TokenRequestHandler tokenRequestHandler)
        {
            return _tokenRequestHandlerDbServices.Update(tokenRequestHandler);
        }

        public bool UpdateTokenRequestSession(TokenRequestSession tokenRequestSession)
        {
            return _tokenRequestSessionDbServices.Update(tokenRequestSession);
        }

        public TokenRequestHandler FindTokenRequestHandlerByAuthorizationCode(string authCode)
        {
            return _tokenRequestHandlerDbServices.FindByAuthorizationCode(authCode);
        }

        public TokenRequestSession FindRequestSessionById(int id)
        {
            return _tokenRequestSessionDbServices.FindById(id);
        }

        public TokenResponse FindRefreshToken(string refreshToken)
        {
            return _tokenResponseDbServices.Find(refreshToken, TokenType.RefreshToken);
        }
    }

    public interface ITokenManager
    {
        object ACF_IssueToken(UserIdentity user, Client client, int currentRequestHandlerId);
        object IssueTokenForRefreshToken(TokenResponse previousRefreshResponse);
        object GenerateIdTokenAndRsaSha256PublicKey(UserIdentity user, string scopeStr, string nonce, string clientid, string authTime = "");
        TokenRequestSession CreateTokenRequestSession();
        TokenRequestHandler GetDraftTokenRequestHandler();
        bool UpdateTokenRequestHandler(TokenRequestHandler tokenRequestHandler);
        bool UpdateTokenRequestSession(TokenRequestSession aCFProcessSession);
        TokenRequestHandler FindTokenRequestHandlerByAuthorizationCode(string authCode);
        TokenRequestSession FindRequestSessionById(int id);
        TokenResponse FindRefreshToken(string refreshToken);
    }
}
