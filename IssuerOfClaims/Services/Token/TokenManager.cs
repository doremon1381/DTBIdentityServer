using Azure.Core;
using IssuerOfClaims.Services.Database;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using ServerDbModels;
using ServerUltilities;
using ServerUltilities.Identity;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace IssuerOfClaims.Services.Token
{
    public class TokenManager : ITokenManager
    {
        private readonly IConfigurationManager _configuration;
        private readonly ITokenResponseDbServices _tokenResponseDbServices;
        private readonly ITokenResponsePerHandlerDbServices _tokensPerIdentityRequestDbServices;
        private readonly ITokenRequestSessionDbServices _tokenRequestSessionDbServices;
        private readonly ITokenRequestHandlerDbServices _tokenRequestHandlerDbServices;
        private readonly IIdTokenDbServices _idTokenDbServices;

        public TokenManager(IConfigurationManager configuration, ITokenResponseDbServices tokenResponseDbServices
            , ITokenResponsePerHandlerDbServices tokenResponsePerHandlerDbServices, ITokenRequestSessionDbServices tokenRequestSessionDbServices
            , ITokenRequestHandlerDbServices tokenRequestHandlerDbServices
            , IIdTokenDbServices idTokenDbServices)
        {
            _configuration = configuration;
            _tokenResponseDbServices = tokenResponseDbServices;
            _tokensPerIdentityRequestDbServices = tokenResponsePerHandlerDbServices;
            _tokenRequestSessionDbServices = tokenRequestSessionDbServices;
            _idTokenDbServices = idTokenDbServices;

            _tokenRequestHandlerDbServices = tokenRequestHandlerDbServices;
        }

        public object IssueToken(UserIdentity user, Client client, int currentRequestHandlerId)
        {
            var currentRequestHandler = _tokenRequestHandlerDbServices.FindById(currentRequestHandlerId);

            // TODO: use this temporary
            IdToken idToken = GetOrCreateIdToken(currentRequestHandler, client.ClientId);

            bool isOfflineAccess = currentRequestHandler.TokenRequestSession.IsOfflineAccess;

            // TODO: I want to reuse token response if it is not expired
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
                // TODO: latest token response does not have refresh token
                if (latestRefreshToken == null
                    || latestRefreshToken.TokenResponse == null)
                {
                    refreshToken = CreateTokenForCurrentResponse(TokenType.RefreshToken);

                    // TODO: latest access token can be used
                    //     : by logic of creation token response, those two (access-refresh token) will go along as a pair
                    if (latestAccessToken != null && latestAccessToken.TokenResponse.TokenExpiried >= DateTime.Now)
                    {
                        accessToken = latestAccessToken.TokenResponse;
                        accessTokenExpiredTime = (latestAccessToken.TokenResponse.TokenExpiried - DateTime.Now).Value.TotalSeconds;
                    }
                    // TODO: latest access token can not be re-used, expired
                    else
                    {
                        // TODO; if expired, create new
                        accessToken = CreateTokenForCurrentResponse(TokenType.AccessToken);
                    }
                }
                // TODO: latest token response has refresh token
                else if (latestRefreshToken != null && latestRefreshToken.TokenResponse != null)
                {
                    // TODO: access token and refresh token can be re-used 
                    if (latestAccessToken.TokenResponse.TokenExpiried >= DateTime.Now
                        && latestRefreshToken.TokenResponse.TokenExpiried >= DateTime.Now)
                    {
                        accessToken = latestAccessToken.TokenResponse;
                        refreshToken = latestRefreshToken.TokenResponse;

                        accessTokenExpiredTime = (accessToken.TokenExpiried - DateTime.Now).Value.TotalSeconds;
                    }
                    // TODO: refresh token can be re-used, but not access token
                    else if (latestAccessToken.TokenResponse.TokenExpiried < DateTime.Now
                            && latestRefreshToken.TokenResponse.TokenExpiried >= DateTime.Now)
                    {
                        // TODO: access token expired time may over the refresh token expired time
                        TimeSpan diff = (TimeSpan)(latestRefreshToken.TokenResponse.TokenExpiried - DateTime.Now);
                        var expiredTime = diff.TotalSeconds < 3600 ? DateTime.Now.AddSeconds(diff.TotalSeconds)
                            : DateTime.Now.AddHours(1);

                        accessToken = CreateTokenForCurrentResponse(TokenType.AccessToken, expiredTime);
                        refreshToken = latestRefreshToken.TokenResponse;
                    }
                    // TODO: neither access token and refresh token cant be re-used
                    else if (latestAccessToken.TokenResponse.TokenExpiried < DateTime.Now
                        && latestRefreshToken.TokenResponse.TokenExpiried < DateTime.Now)
                    {
                        accessToken = CreateTokenForCurrentResponse(TokenType.AccessToken);
                        refreshToken = CreateTokenForCurrentResponse(TokenType.RefreshToken);
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

                responseBody = CreateTokenResponseBody(accessToken.Token, idToken.Token, accessTokenExpiredTime, refreshToken.Token);
            }
            else if (!isOfflineAccess)
            {
                // TODO: latest access token can be used
                if (latestAccessToken != null && latestAccessToken.TokenResponse.TokenExpiried >= DateTime.Now)
                {
                    accessToken = latestAccessToken.TokenResponse;
                }
                else
                {
                    // TODO: re-authenticate
                    accessToken = CreateTokenForCurrentResponse(TokenType.AccessToken);
                }

                responseBody = CreateTokenResponseBody(accessToken.Token, idToken.Token, accessTokenExpiredTime);
            }

            CreateTokenResponsePerIdentityRequest(currentRequestHandler, accessToken);
            CreateTokenResponsePerIdentityRequest(currentRequestHandler, refreshToken);

            currentRequestHandler.TokenRequestSession.IsInLoginSession = false;
            _tokenRequestSessionDbServices.Update(currentRequestHandler.TokenRequestSession);

            return responseBody;
        }

        private IdToken GetOrCreateIdToken(TokenRequestHandler currentRequestHandler, string clientId)
        {
            IdToken idToken;
            if (currentRequestHandler.User.IdToken == null)
            {
                idToken = _idTokenDbServices.GetDraft();
                idToken.CreateTime = currentRequestHandler.User.UpdateTime;
                idToken.User = currentRequestHandler.User;
                idToken.Token = GenerateIdToken(currentRequestHandler.User, currentRequestHandler.TokenRequestSession.Scope, currentRequestHandler.TokenRequestSession.Nonce, clientId);

                _idTokenDbServices.Update(idToken);
            }
            else
                idToken = currentRequestHandler.User.IdToken;

            return idToken;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="tokenResponsePerRequest"></param>
        /// <param name="tokenType"></param>
        /// <param name="manualDateTime">Only use for access token or refresh token</param>
        /// <returns></returns>
        /// <exception cref="InvalidOperationException"></exception>
        private TokenResponse CreateTokenForCurrentResponse(string tokenType, DateTime? manualDateTime = null)
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
            _tokenResponseDbServices.Update(tokenResponse);

            return tokenResponse;
        }

        private void CreateTokenResponsePerIdentityRequest(TokenRequestHandler currentRequestHandler, TokenResponse tokenResponse)
        {
            TokenResponsePerIdentityRequest tokensPerIdentityRequest = _tokensPerIdentityRequestDbServices.GetDraftObject();
            tokensPerIdentityRequest.TokenResponse = tokenResponse;
            tokensPerIdentityRequest.TokenRequestHandler = currentRequestHandler;
            //_token
            //_tokensPerIdentityRequestDbServices.ClearTrack();
            _tokensPerIdentityRequestDbServices.Update(tokensPerIdentityRequest);

            //return tokensPerIdentityRequest;
        }

        /// <summary>
        /// https://openid.net/specs/openid-connect-core-1_0.html
        /// 3.1.3.7.  ID Token Validation
        /// </summary>
        /// <param name="user"></param>
        /// <param name="scopeStr"></param>
        /// <param name="nonce"></param>
        /// <param name="client"></param>
        /// <returns></returns>
        public string GenerateIdToken(UserIdentity user, string scopeStr, string nonce, string clientid)
        {
            try
            {
                // TODO: use rsa256 instead of hs256 for now
                var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]));
                var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
                //var rsa = RSA.Create(2048);
                //var keygen = new SshKeyGenerator.SshKeyGenerator(2048);
                //var privateKey = keygen.ToPrivateKey();
                //Console.WriteLine(privateKey);

                //var publicSshKey = keygen.ToRfcPublicKey();
                //Console.WriteLine(publicSshKey);

                //rsa.ImportRSAPrivateKey(Convert.FromBase64String(_configuration["Jwt:Key"]), out _);
                //RsaSecurityKey key = new RsaSecurityKey(rsa);
                //var credentials = new SigningCredentials(key, SecurityAlgorithms.RsaSha256);
                //var publicKey = Convert.ToBase64String(rsa.ExportRSAPublicKey());
                var scopes = scopeStr.Split(" ");

                var claims = new List<Claim>();

                if (scopes.Contains(IdentityServerConstants.StandardScopes.OpenId))
                {
                    claims.Add(new Claim(JwtClaimTypes.Subject, user.UserName));
                    claims.Add(new Claim(JwtClaimTypes.Audience, clientid));
                    // TODO: hard code for now
                    claims.Add(new Claim(JwtClaimTypes.Issuer, System.Uri.EscapeDataString("https://localhost:7180")));
                }
                if (scopes.Contains(IdentityServerConstants.StandardScopes.Profile))
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
                if (scopes.Contains(IdentityServerConstants.StandardScopes.Email))
                {
                    claims.Add(new Claim(JwtClaimTypes.Email, user.Email));
                    claims.Add(new Claim(JwtClaimTypes.EmailVerified, user.IsEmailConfirmed.ToString()));
                }
                if (scopes.Contains(IdentityServerConstants.StandardScopes.Phone))
                {
                    claims.Add(new Claim(JwtClaimTypes.PhoneNumber, user.PhoneNumber));
                }
                // TOOD: will add later
                if (scopes.Contains(Constants.CustomScope.Role))
                {
                    user.IdentityUserRoles.ToList().ForEach(p =>
                    {
                        claims.Add(new Claim(JwtClaimTypes.Role, p.Role.RoleName));
                    });
                }

                if (!string.IsNullOrEmpty(nonce))
                    claims.Add(new Claim(JwtRegisteredClaimNames.Nonce, nonce));

                var token = new JwtSecurityToken(_configuration["Jwt:Issuer"],
                    _configuration["Jwt:Audience"],
                    claims,
                    expires: null,
                    signingCredentials: credentials);

                return new JwtSecurityTokenHandler().WriteToken(token);
            }
            catch (Exception ex)
            {
                throw new Exception(ex.Message);
            }
        }

        private object CreateTokenResponseBody(string access_token, string id_token, double expired_in, string refresh_token = "")
        {
            object responseBody;
            if (string.IsNullOrEmpty(refresh_token))
            {
                responseBody = new
                {
                    access_token = access_token,
                    id_token = id_token,
                    token_type = "Bearer",
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
    }

    public interface ITokenManager
    {
        object IssueToken(UserIdentity user, Client client, int currentRequestHandlerId);
        string GenerateIdToken(UserIdentity user, string scopeStr, string nonce, string clientid);
        TokenRequestSession CreateTokenRequestSession();
        TokenRequestHandler GetDraftTokenRequestHandler();
        bool UpdateTokenRequestHandler(TokenRequestHandler tokenRequestHandler);
        bool UpdateTokenRequestSession(TokenRequestSession aCFProcessSession);
        TokenRequestHandler FindTokenRequestHandlerByAuthorizationCode(string authCode);
        TokenRequestSession FindRequestSessionById(int id);
    }
}
