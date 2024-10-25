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
using System.Text;
using System.Net;
using IssuerOfClaims.Models;

namespace IssuerOfClaims.Services.Token
{
    /// <summary>
    /// Issue id token, refresh token and access token
    /// </summary>
    public class TokenManager : ITokenManager
    {
        private readonly ITokenResponseDbServices _tokenResponseDbServices;
        private readonly ITokenForRequestHandlerDbServices _tokensPerIdentityRequestDbServices;
        private readonly IIdentityRequestSessionDbServices _identityRequestSessionDbServices;
        private readonly IIdentityRequestHandlerDbServices _tokenRequestHandlerDbServices;
        private readonly GoogleClientConfiguration _googleClientConfiguration;

        public TokenManager(ITokenResponseDbServices tokenResponseDbServices
            , ITokenForRequestHandlerDbServices tokenResponsePerHandlerDbServices, IIdentityRequestSessionDbServices tokenRequestSessionDbServices
            , IIdentityRequestHandlerDbServices tokenRequestHandlerDbServices
            , GoogleClientConfiguration googleClientSettings)
        {
            _tokenResponseDbServices = tokenResponseDbServices;
            _tokensPerIdentityRequestDbServices = tokenResponsePerHandlerDbServices;
            _identityRequestSessionDbServices = tokenRequestSessionDbServices;

            _tokenRequestHandlerDbServices = tokenRequestHandlerDbServices;

            _googleClientConfiguration = googleClientSettings;
        }

        // TODO: will check again
        public async Task<string> IssueTokenForRefreshToken(TokenResponse currentRefreshToken)
        {
            ValidateRefreshToken(currentRefreshToken);

            var lastestRefreshTokenBeUsed = currentRefreshToken.TokensPerIdentityRequests.Last();
            var tokenRequestHandler = _tokenRequestHandlerDbServices.FindById(lastestRefreshTokenBeUsed.IdentityRequestHandlerId);

            // create new id token, remove the old, add the new into previous authenticate session
            // create new access token if it's expired, if access token is created new, remove the old, add the new one into previous authenticate session
            // create new refresh token if it's expired, if refresh token is created new, remove the old, add the new one into previous authenticate session

            var accessToken = RefreshAccessToken_IssuseToken(tokenRequestHandler, tokenRequestHandler.TokensPerRequestHandlers.First(t => t.TokenResponse.TokenType.Equals(OidcConstants.TokenTypes.AccessToken)), OidcConstants.TokenTypes.AccessToken);
            var idToken = RefreshAccessToken_IssuseIdToken(tokenRequestHandler, tokenRequestHandler.TokensPerRequestHandlers.First(t => t.TokenResponse.TokenType.Equals(OidcConstants.TokenTypes.IdentityToken)));

            var responseBody = await Utilities.CreateTokenResponseStringAsync(accessToken.Token, idToken.Token, accessToken.TokenExpiried);

            return responseBody;
        }

        private void ValidateRefreshToken(TokenResponse currentRefreshToken)
        {
            if (currentRefreshToken.TokenExpiried <= DateTime.Now)
                throw new CustomException(ExceptionMessage.REFRESH_TOKEN_EXPIRED, HttpStatusCode.Unauthorized);
        }

        /// <summary>
        /// TODO: for now
        /// </summary>
        /// <param name="currentRequestHandler"></param>
        /// <returns></returns>
        private TokenResponse RefreshAccessToken_IssuseIdToken(IdentityRequestHandler currentRequestHandler, TokenForRequestHandler tokenResponsePerIdentityRequest)
        {
            TokenResponse idToken = CreateToken(OidcConstants.TokenTypes.IdentityToken);
            var idTokenValue = GenerateIdTokenAsync(currentRequestHandler.User, currentRequestHandler.RequestSession.Scope, ""
                , currentRequestHandler.Client.ClientId, currentRequestHandler.SuccessAt.Value.ToString()).Result;

            idToken.Token = idTokenValue;

            _tokenResponseDbServices.Update(idToken);
            // TODO: will check again
            //_tokenResponseDbServices.Delete(tokenResponsePerIdentityRequest.TokenResponse);

            CreateTokenResponsePerIdentityRequest(currentRequestHandler, idToken);

            return idToken;
        }

        private TokenResponse RefreshAccessToken_IssuseToken(IdentityRequestHandler tokenRequestHandler, TokenForRequestHandler tokenResponsePerIdentityRequest, string tokenType)
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

        public string ACF_IssueToken(Guid userId, Guid idOfClient, string clientId, Guid currentRequestHandlerId)
        {
            var currentRequestHandler = _tokenRequestHandlerDbServices.FindById(currentRequestHandlerId);

            // TODO: use this temporary
            TokenResponse idToken = ACF_CreateIdToken(currentRequestHandler, clientId);

            bool isOfflineAccess = currentRequestHandler.RequestSession.IsOfflineAccess;

            // I want to reuse token response if it is not expired
            var latestRefreshToken = _tokensPerIdentityRequestDbServices.FindLast(userId, idOfClient, needAccessToken: false);
            var latestAccessToken = _tokensPerIdentityRequestDbServices.FindLast(userId, idOfClient, needAccessToken: true);

            TokenResponse refreshToken = null;
            TokenResponse accessToken = null;

            // TODO: at this step, need to check offline_access is inside authrization login request is true or fault
            //     : if fault, then response will not include refresh token
            //     : if true, then add refresh token along with response
            if (isOfflineAccess)
            {
                // latest token response does not have refresh token
                if (latestRefreshToken == null
                    || latestRefreshToken.TokenResponse == null)
                {
                    refreshToken = CreateToken(OidcConstants.TokenTypes.RefreshToken);

                    // latest access token can be used
                    // , by logic of creation token response, those two (access-refresh token) will go along as a pair
                    if (latestAccessToken != null && latestAccessToken.TokenResponse.TokenExpiried > DateTime.Now)
                    {
                        accessToken = latestAccessToken.TokenResponse;
                    }
                    // latest access token can not be re-used, expired
                    else
                    {
                        // if expired, create new
                        accessToken = CreateToken(OidcConstants.TokenTypes.AccessToken);
                    }
                }
                // latest token response has refresh token
                else if (latestRefreshToken != null && latestRefreshToken.TokenResponse != null)
                {
                    // access token and refresh token can be re-used 
                    if (latestAccessToken.TokenResponse.TokenExpiried > DateTime.Now
                        && latestRefreshToken.TokenResponse.TokenExpiried > DateTime.Now)
                    {
                        accessToken = latestAccessToken.TokenResponse;
                        refreshToken = latestRefreshToken.TokenResponse;
                    }
                    // refresh token can be re-used, but not access token
                    else if (latestAccessToken.TokenResponse.TokenExpiried <= DateTime.Now
                            && latestRefreshToken.TokenResponse.TokenExpiried > DateTime.Now)
                    {
                        // access token expired time may over the refresh token expired time
                        TimeSpan diff = (TimeSpan)(latestRefreshToken.TokenResponse.TokenExpiried - DateTime.Now);
                        var expiredTime = diff.TotalSeconds < 3600 ? DateTime.Now.AddSeconds(diff.TotalSeconds)
                            : DateTime.Now.AddHours(1);

                        accessToken = CreateToken(OidcConstants.TokenTypes.AccessToken, expiredTime);
                        refreshToken = latestRefreshToken.TokenResponse;
                    }
                    // neither access token and refresh token cant be re-used
                    else if (latestAccessToken.TokenResponse.TokenExpiried <= DateTime.Now
                        && latestRefreshToken.TokenResponse.TokenExpiried <= DateTime.Now)
                    {
                        accessToken = CreateToken(OidcConstants.TokenTypes.AccessToken);
                        refreshToken = CreateToken(OidcConstants.TokenTypes.RefreshToken);
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
            }
            else if (!isOfflineAccess)
            {
                // latest access token can be used
                if (latestAccessToken != null && latestAccessToken.TokenResponse.TokenExpiried > DateTime.Now)
                    accessToken = latestAccessToken.TokenResponse;
                else
                {
                    // create new 
                    accessToken = CreateToken(OidcConstants.TokenTypes.AccessToken);
                }
            }

#pragma warning disable CS8602 // Dereference of a possibly null reference.
            // TODO: at this step, if accessToken is null, then something is wrong!
            var responseBody = Utilities.CreateTokenResponseStringAsync(accessToken.Token, idToken.Token, accessToken.TokenExpiried, refreshToken == null ? "" : refreshToken.Token).Result;
#pragma warning restore CS8602 // Dereference of a possibly null reference.

            CreateTokenResponsePerIdentityRequest(currentRequestHandler, accessToken);
            CreateTokenResponsePerIdentityRequest(currentRequestHandler, refreshToken);
            // TODO: will think about how to handle idtoken, create one for user, update when information of user is changed or sth else
            CreateTokenResponsePerIdentityRequest(currentRequestHandler, idToken);

            currentRequestHandler.RequestSession.IsInLoginSession = false;
            _identityRequestSessionDbServices.Update(currentRequestHandler.RequestSession);

            return responseBody;
        }

        // TODO: https://openid.net/specs/openid-connect-core-1_0.html#TokenResponse
        //     : following 3.1.3.3.  Successful Token Response
        //     : ID Token value associated with the authenticated session.
        private TokenResponse ACF_CreateIdToken(IdentityRequestHandler currentRequestHandler, string clientId)
        {
            TokenResponse tokenResponse = CreateToken(OidcConstants.TokenTypes.IdentityToken);
            var idToken = GenerateIdTokenAsync(currentRequestHandler.User, currentRequestHandler.RequestSession.Scope, currentRequestHandler.RequestSession.Nonce, clientId).Result;
            tokenResponse.Token = idToken;

            _tokenResponseDbServices.Update(tokenResponse);

            return tokenResponse;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="tokenResponsePerRequest"></param>
        /// <param name="tokenType"></param>
        /// <param name="expiredTime">Only use for access token or refresh token</param>
        /// <returns></returns>
        /// <exception cref="InvalidOperationException"></exception>
        private TokenResponse CreateToken(string tokenType, DateTime? expiredTime = null, DateTime? issueAt = null)
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

        private void CreateTokenResponsePerIdentityRequest(IdentityRequestHandler currentRequestHandler, TokenResponse tokenResponse)
        {
            TokenForRequestHandler tokensPerIdentityRequest = _tokensPerIdentityRequestDbServices.GetDraftObject();
            tokensPerIdentityRequest.TokenResponse = tokenResponse;
            tokensPerIdentityRequest.IdentityRequestHandler = currentRequestHandler;

            _tokensPerIdentityRequestDbServices.Update(tokensPerIdentityRequest);
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
                var claims = await CreateClaimsForIdTokenAsync(user, nonce, authTime, scope, clientId);

                var publicPrivateKeys = await CreateRsaPublicKeyAndPrivateKey();

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

                return jwt;
            }
            catch (Exception ex)
            {
                throw new Exception(ex.Message);
            }
        }

        private static async Task<IDictionary<string, object>> CreateClaimsForIdTokenAsync(UserIdentity user, string nonce, string authTime, string scope, string clientId)
        {
            var claims = new List<Claim>();
            var scopeVariables = scope.Split(" ");

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

        #region Implement RsaSha256, powered by copilot
        /// <summary>
        /// for this pair, key is rsa private key, value is rsa public key
        /// </summary>
        /// <returns></returns>
        private static async Task<KeyValuePair<RSAParameters, RSAParameters>> CreateRsaPublicKeyAndPrivateKey()
        {
            RSAParameters publicKey;
            RSAParameters privateKey;

            if (KeyIsMissingOrExpired())
            {
                using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
                {
                    // Get the public and private key
                    publicKey = rsa.ExportParameters(false); // Public key
                    privateKey = rsa.ExportParameters(true); // Private key

                    // Store or distribute these keys securely                
                }

                ExportJsonKey(publicKey);
                ExportJsonKey(privateKey, isPublicKey: false);
            }
            else
            {
                publicKey = ReadJsonKey(); // Public key
                privateKey = ReadJsonKey(isPublicKey: false); // Private key
            }

            return new KeyValuePair<RSAParameters, RSAParameters>(privateKey, publicKey);
        }

        private static bool KeyIsMissingOrExpired(bool isPublicKey = true)
        {
            FileInfo keyFile = new FileInfo(GetKeyFilePath(isPublicKey));

            if (keyFile.Exists)
            {
                if (keyFile.CreationTime.AddDays(15) > DateTime.Now)
                    return false;
            }

            return true;
        }

        private static string GetKeyFilePath(bool isPublicKey)
        {
            return isPublicKey switch
            {
                true => $"{Environment.CurrentDirectory}\\Services\\Token\\RsaSha256Keys\\Rsa_publicKey.json",
                false => $"{Environment.CurrentDirectory}\\Services\\Token\\RsaSha256Keys\\Rsa_privateKey.json",
            };
        }

        private static void ExportJsonKey(RSAParameters key, bool isPublicKey = true)
        {
            FileInfo keyFile = new FileInfo(GetKeyFilePath(isPublicKey));

            using (FileStream fs = keyFile.Open(FileMode.Create))
            {
                var contents = JsonConvert.SerializeObject(key);
                Byte[] bytes = new UTF8Encoding(true).GetBytes(contents);

                fs.Write(bytes, 0, bytes.Length);
            }
        }

        private static RSAParameters ReadJsonKey(bool isPublicKey = true)
        {
            FileInfo keyFile = new FileInfo(GetKeyFilePath(isPublicKey));
            RSAParameters result = default;
            if (keyFile.Exists)
            {
                var text = keyFile.OpenText().ReadToEnd();
                result = JsonConvert.DeserializeObject<RSAParameters>(text);
            }
            // TODO: will check again
            else
                throw new CustomException("public key is missing!", HttpStatusCode.InternalServerError);

            return result;
        }

        private async Task<object> GetJsonPublicKeyAsync(RSAParameters publicKey)
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

        public IdentityRequestSession CreateRequestSession(Guid requestHandlerId)
        {
            return _identityRequestSessionDbServices.CreateTokenRequestSession(requestHandlerId);
        }

        public IdentityRequestHandler GetDraftRequestHandler()
        {
            return _tokenRequestHandlerDbServices.GetDraftObject();
        }

        public bool UpdateRequestHandler(IdentityRequestHandler tokenRequestHandler)
        {
            return _tokenRequestHandlerDbServices.Update(tokenRequestHandler);
        }

        public bool UpdateRequestSession(IdentityRequestSession tokenRequestSession)
        {
            return _identityRequestSessionDbServices.Update(tokenRequestSession);
        }

        public IdentityRequestHandler FindRequestHandlerByAuthorizationCode(string authCode)
        {
            return _tokenRequestHandlerDbServices.FindByAuthorizationCode(authCode);
        }

        public IdentityRequestSession FindRequestSessionById(int id)
        {
            return _identityRequestSessionDbServices.FindById(id);
        }

        public TokenResponse FindRefreshToken(string refreshToken)
        {
            return _tokenResponseDbServices.Find(refreshToken, OidcConstants.TokenTypes.RefreshToken);
        }

        public RSAParameters GetPublicKeyJson()
        {
            return ReadJsonKey(); // Public key
        }

        public IdentityRequestSession GetDraftRequestSession()
        {
            return _identityRequestSessionDbServices.GetDraft();
        }

        #region Google save token to database
        public bool SaveTokenFromExternalSource(string accessToken, string refreshToken, string idToken,
            long idToken_issuedAtTimeSeconds, long idToken_expirationTimeSeconds, DateTime accessTokenIssueAt, DateTime accessTokenExpiredIn
            , IdentityRequestHandler requestHandler, string externalSource)
        {
            var _accessToken = SaveExternalSourceToken(accessToken, accessTokenIssueAt, accessTokenExpiredIn, externalSource, OidcConstants.TokenTypes.AccessToken);
            var _idToken = SaveExternalSourceToken(idToken, Utilities.Google_TimeSecondsToDateTime(idToken_issuedAtTimeSeconds), Utilities.Google_TimeSecondsToDateTime(idToken_expirationTimeSeconds), externalSource, OidcConstants.TokenTypes.IdentityToken);

            if (refreshToken != null)
            {
                var _refreshToken = SaveExternalSourceToken(accessToken, null, null, externalSource, OidcConstants.TokenTypes.RefreshToken);
                CreateTokenResponsePerIdentityRequest(requestHandler, _refreshToken);
            }

            CreateTokenResponsePerIdentityRequest(requestHandler, _accessToken);
            // TODO: will think about how to handle idtoken, create one for user, update when information of user is changed or sth else
            CreateTokenResponsePerIdentityRequest(requestHandler, _idToken);

            return true;
        }

        private TokenResponse SaveExternalSourceToken(string tokenValue, DateTime? issueAt, DateTime? expiredTime, string externalSource, string tokenType)
        {
            var token = CreateToken(tokenType, expiredTime, issueAt);
            token.Token = tokenValue;
            token.ExternalSource = externalSource;

            return token;
        }
        #endregion

        #region Google refresh access token
        public async Task<string> RefreshAccessTokenFromExternalSourceAsync(string refreshToken, string externalSource)
        {
            ValidateRefreshToken(refreshToken);
            // send request to google to refresh access token 
            var token = externalSource switch
            {
                ExternalSources.Google => await Google_RefershAccessToken(refreshToken),
                _ => throw new CustomException("Other external source is not implemented!", HttpStatusCode.NotImplemented)
            };
            return token;
        }

        private static bool ValidateRefreshToken(string refreshToken)
        {
            if (string.IsNullOrEmpty(refreshToken))
                throw new CustomException("Refresh Token is null or empty", HttpStatusCode.NotAcceptable);

            return true;
        }

        private async Task<string> Google_RefershAccessToken(string refreshToken)
        {
            var content = string.Format("client_id={0}&client_secret={1}&refresh_token={2}&grant_type=refresh_token"
                , _googleClientConfiguration.ClientId
                , _googleClientConfiguration.ClientSecret
                , refreshToken);

            HttpWebRequest refreshRequest = (HttpWebRequest)WebRequest.Create(_googleClientConfiguration.TokenUri);
            refreshRequest.Method = "POST";
            refreshRequest.ContentType = "application/x-www-form-urlencoded";
            refreshRequest.Accept = "Accept=text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
            byte[] bytes = Encoding.ASCII.GetBytes(content);
            refreshRequest.ContentLength = bytes.Length;
            var stream = refreshRequest.GetRequestStream();
            await stream.WriteAsync(bytes, 0, bytes.Length);
            stream.Close();

            string responseText = "";

            WebResponse response = await refreshRequest.GetResponseAsync();
            using(StreamReader reader = new StreamReader(response.GetResponseStream()))
            {
                responseText = await reader.ReadToEndAsync();
            }

            return responseText;
        }
        #endregion

        public string IGF_IssueToken(string state, IdentityRequestHandler requestHandler)
        {
            var accessToken = CreateToken(OidcConstants.TokenTypes.AccessToken);
            CreateTokenResponsePerIdentityRequest(requestHandler, accessToken);

            return accessToken.Token;
        }
    }

    public interface ITokenManager
    {
        string ACF_IssueToken(Guid userId, Guid idOfClient, string clientId, Guid currentRequestHandlerId);
        bool SaveTokenFromExternalSource(string accessToken, string refreshToken, string idToken, long idToken_issuedAtTimeSeconds, long idToken_expirationTimeSeconds, DateTime accessTokenIssueAt, DateTime accessTokenExpiredIn, IdentityRequestHandler requestHandler, string externalSource);
        Task<string> IssueTokenForRefreshToken(TokenResponse previousRefreshResponse);
        Task<string> GenerateIdTokenAsync(UserIdentity user, string scopeStr, string nonce, string clientid, string authTime = "");
        IdentityRequestSession GetDraftRequestSession();
        IdentityRequestSession CreateRequestSession(Guid requestHandlerId);
        IdentityRequestHandler GetDraftRequestHandler();
        bool UpdateRequestHandler(IdentityRequestHandler tokenRequestHandler);
        bool UpdateRequestSession(IdentityRequestSession aCFProcessSession);
        IdentityRequestHandler FindRequestHandlerByAuthorizationCode(string authCode);
        IdentityRequestSession FindRequestSessionById(int id);
        TokenResponse FindRefreshToken(string refreshToken);
        RSAParameters GetPublicKeyJson();
        Task<string> RefreshAccessTokenFromExternalSourceAsync(string refreshToken, string externalSource);
        string IGF_IssueToken(string state, IdentityRequestHandler requestHandler);
    }
}
