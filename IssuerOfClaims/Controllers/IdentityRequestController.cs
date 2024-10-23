using IssuerOfClaims.Controllers.Ultility;
using ServerUltilities.Extensions;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using ServerDbModels;
using ServerUltilities;
using ServerUltilities.Identity;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using IssuerOfClaims.Services.Database;
using IssuerOfClaims.Extensions;
using IssuerOfClaims.Services.Token;
using static ServerUltilities.Identity.OidcConstants;
using IssuerOfClaims.Services;
using Microsoft.IdentityModel.Tokens;
using IssuerOfClaims.Models;
using Google.Apis.Auth;
using IssuerOfClaims.Models.Request;
using System.Net.WebSockets;
using static ServerUltilities.Identity.Constants;

namespace IssuerOfClaims.Controllers
{
    [ApiController]
    [Route("[controller]")]
    //[ApiVersion("1.0")]
    [ControllerName(ProtocolRoutePaths.OauthPathPrefix)]
    //[EnableCors("MyPolicy")]
    // TODO: https://openid.net/specs/openid-connect-core-1_0.html
    //     : try to implement from this specs
    //     : for now, I dont intend to add https://datatracker.ietf.org/doc/html/rfc8414 (response for a request for "/.well-known/oauth-authorization-server"), I will think about it late
    public class IdentityRequestController : ControllerBase
    {
        private readonly ILogger<IdentityRequestController> _logger;

        private readonly IApplicationUserManager _applicationUserManager;
        private readonly IConfigurationManager _configuration;
        private readonly ITokenManager _tokenManager;
        private readonly IClientDbServices _clientDbServices;
        private readonly IEmailServices _emailServices;

        public IdentityRequestController(ILogger<IdentityRequestController> logger, IConfigurationManager configuration
            , IApplicationUserManager userManager
            , ITokenManager tokenManager, IEmailServices emailServices
            , IClientDbServices clientDbServices)
        {
            _logger = logger;
            _configuration = configuration;

            _applicationUserManager = userManager;
            _clientDbServices = clientDbServices;
            _emailServices = emailServices;

            _tokenManager = tokenManager;
        }

        #region catch authorize request
        /// <summary>
        /// authorization_endpoint
        /// https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
        /// Authentication Request Validation
        /// </summary>
        /// <returns></returns>
        [HttpGet("authorize")]
        [Authorize]
        public async Task<ActionResult> AuthorizationAsync()
        {
            // 1. Get authorization request from server
            // 2. Return an http 302 message to server, give it a nonce cookie (for now, ignore this part),
            //    if asking for google, then send a redirect to google to get authorization code
            //    if basic access (I mean implicit grant - form_post or not), then return a redirect to another request to identity server - send request to "authentication/basicAccess" route
            // 3. With many account can be found in one useragent (chrome or ...) - for example, using more than one google account when using google authentication without explicit authuser as request parameter
            //  , need to open a consent prompt to let resource owner chooses which one will be used for authorization request.
            //  With the way I want to use web application, I will not let more than one user interacts with server in one useragent.
            //  So basically, I can use "none" as prompt value by defualt, but will think about some changes in future.

            AuthCodeParameters parameters = new AuthCodeParameters(HttpContext.Request.QueryString.Value);

            var client = _clientDbServices.Find(parameters.ClientId.Value);

            ACF_I_VerifyRedirectUris(parameters.RedirectUri.Value, client);

            switch (GetMappingGrantType(parameters.ResponseType.Value))
            {
                case GrantType.Implicit:
                    return await ImplicitGrantAsync(parameters);
                case GrantType.ClientCredentials:
                    throw new CustomException(ExceptionMessage.NOT_IMPLEMENTED, HttpStatusCode.NotImplemented);
                case GrantType.Hybrid:
                    throw new CustomException(ExceptionMessage.NOT_IMPLEMENTED, HttpStatusCode.NotImplemented);
                case GrantType.AuthorizationCode:
                    return await IssueAuthorizationCodeAsync(parameters);
                default:
                    throw new CustomException(ExceptionMessage.NOT_IMPLEMENTED, HttpStatusCode.NotImplemented);
            }
        }

        private static string GetMappingGrantType(string responseType)
        {
            return Constants.ResponseTypeToGrantTypeMapping[responseType];
        }

        private static void ACF_I_VerifyRedirectUris(string redirectUri, Client client)
        {
            IEnumerable<Uri> redirectUris = client.RedirectUris.Split(",").Select(r => new Uri(r));
            Uri requestUri = new Uri(redirectUri);

            if (!ACF_RedirectUriIsRegistered(redirectUris, requestUri))
                throw new CustomException(ExceptionMessage.REDIRECTURI_IS_MISMATCH, HttpStatusCode.BadRequest);
        }

        private static bool ACF_RedirectUriIsRegistered(IEnumerable<Uri> redirectUris, Uri requestUri)
        {
            return redirectUris.FirstOrDefault(r => r.Host.Equals(requestUri.Host) && r.AbsolutePath.Equals(requestUri.AbsolutePath)) != null;
        }
        #endregion

        #region Issue authorization code
        /// <summary>
        /// TODO: Authorization Server Authenticates End-User: https://openid.net/specs/openid-connect-core-1_0.html
        /// </summary>
        /// <param name="requestQuerry"></param>
        /// <param name="responseMode"></param>
        /// <param name="redirectUri"></param>
        /// <param name="state"></param>
        /// <param name="scope"></param>
        /// <param name="nonce"></param>
        /// <param name="headers"></param>
        /// <returns></returns>
        private async Task<ActionResult> IssueAuthorizationCodeAsync(AuthCodeParameters @params)
        {
            // TODO: comment for now
            //     : by using AuthenticateHanlder, in this step, authenticated is done
            //     : get user, create authorization code, save it to login session and out

            UserIdentity user = await ACF_I_GetResourceOwnerIdentity();
            var client = _clientDbServices.Find(@params.ClientId.Value);

            ACF_I_ValidateScopes(@params.Scope.Value, client);

            var requestHandler = ACF_I_CreateTokenRequestHandler(user, client);
            var acfProcessSession = _tokenManager.CreateTokenRequestSession(requestHandler.Id);

            ACF_I_UpdateRequestSessionDetails(@params, acfProcessSession, out string authorizationCode);

            // TODO: will check again
            await ACF_I_SendResponseBaseOnResponseModeAsync(@params, authorizationCode);

            // WRONG IMPLEMENT!
            // TODO: if following openid specs, I will need to return responseBody as query or fragment inside uri
            //     , but currently I don't know particular form of the response
            //     , so if it 's considered a bug, I will fix it later
            //return StatusCode((int)HttpStatusCode.OK, System.Text.Json.JsonSerializer.Serialize(responseBody));
            return new EmptyResult();
        }

        private static async Task ACF_I_SendResponseBaseOnResponseModeAsync(AuthCodeParameters @params, string authorizationCode)
        {
            string responseMessage = await ACF_I_CreateRedirectContentAsync("", @params.ResponseMode.Value, @params.State.Value, authorizationCode, @params.Scope.Value, @params.Prompt.Value);

            // TODO: need to send another request to redirect uri, contain fragment or query
            ACF_I_HttpClientOnDuty(@params.RedirectUri.Value, responseMessage);
            // TODO: will trying to use socket
            //await ACF_SocketOnDuty(responseMessage, @params.RedirectUri.Value);
        }

        /// <summary>
        /// TODO: currently, I take advantage of fired and forget action, but will think about it later.
        /// </summary>
        /// <param name="params"></param>
        /// <param name="redirectContent"></param>
        private static void ACF_I_HttpClientOnDuty(string redirectUri, string redirectContent)
        {
            // Usage:
            HttpClient httpClient = new HttpClient();
            httpClient.BaseAddress = new Uri(redirectUri);
            httpClient.Timeout = TimeSpan.FromMilliseconds(10);
            httpClient.GetAsync(redirectContent);
        }

        private static async Task ACF_SocketOnDuty(string message, string address = "", int port = 80)
        {
            ClientWebSocket webSocket = null;
            try
            {
                webSocket = new ClientWebSocket();
                await webSocket.ConnectAsync(new Uri(address.Replace("http", "ws")), CancellationToken.None);
                await Send(webSocket, message);
            }
            catch (Exception ex)
            {
                throw new CustomException(ex.Message, HttpStatusCode.InternalServerError);
            }
        }

        private static async Task Send(ClientWebSocket webSocket, string responseMessage)
        {
            if (webSocket.State == WebSocketState.Open)
            {
                //string response = "";
                byte[] buffer = UTF8Encoding.UTF8.GetBytes(responseMessage);

                webSocket.SendAsync(buffer, WebSocketMessageType.Binary, false, CancellationToken.None);
            }
        }

        private static async Task<string> ACF_I_CreateRedirectContentAsync(string redirectUri, string responseMode, string state, string authorizationCode, string scope, string prompt)
        {
            string seprate = GetSeparatorByResponseMode(responseMode);

            StringBuilder builder = new StringBuilder($"{redirectUri}{seprate}code={authorizationCode}");
            builder.Append(string.IsNullOrEmpty(state) ? "" : $"&state={state}");
            builder.Append($"&scope={scope}");
            builder.Append($"&prompt={prompt}");

            return builder.ToString();
        }

        private async Task<UserIdentity> ACF_I_GetResourceOwnerIdentity()
        {
            var obj = await _applicationUserManager.Current.GetUserAsync(HttpContext.User);

            if (obj == null)
                throw new InvalidDataException(ExceptionMessage.USER_NULL);

            return obj;
        }

        private static bool ACF_I_ValidateScopes(string scopes, Client client)
        {
            var variables = scopes.Split(" ");
            foreach (var s in variables)
            {
                if (!client.AllowedScopes.Contains(s))
                    throw new InvalidDataException(ExceptionMessage.SCOPES_NOT_ALLOWED);
            }
            return true;
        }
        /// <summary>
        /// TODO: will fix some error when adding transient or scopped dbcontext
        /// </summary>
        /// <param name="user"></param>
        /// <param name="ACFProcessSession"></param>
        private IdentityRequestHandler ACF_I_CreateTokenRequestHandler(UserIdentity user, Client client)
        //, IdentityRequestSession ACFProcessSession)
        {
            var tokenRequestHandler = _tokenManager.GetDraftTokenRequestHandler();
            tokenRequestHandler.User = user;
            // TODO: will check again
            tokenRequestHandler.Client = client;

            // TODO: will check again
            _tokenManager.UpdateTokenRequestHandler(tokenRequestHandler);

            return tokenRequestHandler;
        }
        private void ACF_I_UpdateRequestSessionDetails(AuthCodeParameters parameters, IdentityRequestSession ACFProcessSession, out string authorizationCode)
        {
            ACF_I_ImportPKCERequestedParams(parameters.CodeChallenge.Value, parameters.CodeChallengeMethod.Value, parameters.CodeChallenge.HasValue, ACFProcessSession);
            ACF_I_ImportRequestSessionData(parameters.Scope.Value, parameters.Nonce.Value, ACFProcessSession, parameters.RedirectUri.Value, out authorizationCode);

            _tokenManager.UpdateTokenRequestSession(ACFProcessSession);
        }
        private static void ACF_I_ImportRequestSessionData(string scope, string nonce, IdentityRequestSession tokenRequestSession, string redirectUri, out string authorizationCode)
        {
            // TODO: create authorization code
            authorizationCode = RNGCryptoServicesUltilities.RandomStringGeneratingWithLength(32);

            tokenRequestSession.AuthorizationCode = authorizationCode;
            tokenRequestSession.Nonce = nonce;
            tokenRequestSession.RedirectUri = redirectUri;
            tokenRequestSession.Scope = scope;
            tokenRequestSession.IsOfflineAccess = scope.Contains(OidcConstants.StandardScopes.OfflineAccess);
        }

        private static void ACF_I_ImportPKCERequestedParams(string codeChallenge, string codeChallengeMethod, bool codeChallenge_HasValue, IdentityRequestSession tokenRequestSession)
        {
            if (codeChallenge_HasValue)
            {
                tokenRequestSession.CodeChallenge = codeChallenge;
                tokenRequestSession.CodeChallengeMethod = codeChallengeMethod;
            }
        }
        #endregion

        #region implicit grant
        /// <summary>
        /// TODO: not yet done
        /// </summary>
        /// <param name="requestQuerry"></param>
        /// <param name="responseMode"></param>
        /// <param name="redirectUri"></param>
        /// <param name="state"></param>
        /// <param name="scope"></param>
        /// <param name="nonce"></param>
        /// <param name="clientId"></param>
        /// <param name="headers"></param>
        /// <returns></returns>
        private async Task<ActionResult> ImplicitGrantAsync(AuthCodeParameters parameters)
        {
            // TODO: for this situation, Thread and http context may not need
            var principal = HttpContext.User;

            var user = await _applicationUserManager.Current.GetUserAsync(principal);
            var client = _clientDbServices.Find(parameters.ClientId.Value);

            // TODO: scope is used for getting claims to send to client,
            //     : for example, if scope is missing email, then in id_token which will be sent to client will not contain email's information 
            var idToken = await _tokenManager.GenerateIdTokenAsync(user, parameters.Scope.Value, parameters.Nonce.Value, client.ClientId);

            // TODO: update must follow order, I will explain late
            var requestHandler = IGF_UpdateTokenRequestHandler(user, client, idToken);
            IGF_CreateRequestSession(requestHandler.Id, client.AllowedScopes);

            var accessToken = _tokenManager.IGF_IssueToken(parameters.State.Value, requestHandler);

            // Check response mode to know what kind of response is going to be used
            // return a form_post, url fragment or body of response
            string responseMessage = "";

            if (parameters.ResponseMode.Value.Equals(ResponseModes.FormPost))
            {
                responseMessage = GetFormPostHtml(parameters.RedirectUri.Value, new Dictionary<string, string>()
                {
                    { AuthorizeResponse.AccessToken, accessToken },
                    { AuthorizeResponse.TokenType, OidcConstants.TokenResponse.BearerTokenType },
                    { AuthorizeResponse.IdentityToken, idToken },
                    { AuthorizeResponse.State, parameters.State.Value }
                });
            }
            else
            {
                int expiredIn = 3600;
                responseMessage = await IGF_CreateRedirectContentAsync(accessToken, OidcConstants.TokenResponse.BearerTokenType, parameters.State.Value, idToken, expiredIn, parameters.ResponseMode.Value, parameters.RedirectUri.Value);
            }

            HttpContext.Response.StatusCode = (int)HttpStatusCode.Redirect;
            // TODO: will learn how to use this function
            await WriteHtmlAsync(HttpContext.Response, responseMessage);
            // TODO: will learn how to use it later
            return new EmptyResult();
        }

        private async Task<string> IGF_CreateRedirectContentAsync(string accessToken, string bearerTokenType, string state, string idToken, int expiredIn, string responseMode, string redirectUri)
        {
            string seprate = GetSeparatorByResponseMode(responseMode);

            StringBuilder builder = new StringBuilder($"{redirectUri}{seprate}{AuthorizeResponse.AccessToken}={accessToken}");
            builder.Append($"&{AuthorizeResponse.TokenType}={bearerTokenType}");
            builder.Append($"&{AuthorizeResponse.ExpiresIn}={expiredIn}");
            builder.Append($"&{AuthorizeResponse.IdentityToken}={idToken}");
            builder.Append(string.IsNullOrEmpty(state) ? "" : $"&{AuthorizeResponse.State}={state}");

            return builder.ToString();
        }

        private static string GetSeparatorByResponseMode(string responseMode)
        {
            return responseMode switch
            {
                ResponseModes.Query => "?",
                ResponseModes.Fragment => "#",
                _ => throw new CustomException(ExceptionMessage.RESPONSE_MODE_NOT_ALLOWED)
            };
        }

        private IdentityRequestHandler IGF_UpdateTokenRequestHandler(UserIdentity user, Client client, string idToken)
        {
            var requestHandler = _tokenManager.GetDraftTokenRequestHandler();
            requestHandler.User = user;
            requestHandler.Client = client;
            //
            _tokenManager.UpdateTokenRequestHandler(requestHandler);

            return requestHandler;
        }

        // TODO: will test again
        private void IGF_CreateRequestSession(Guid tokenRequestHandlerId, string allowedScopes)
        {
            var tokenRequestSession = _tokenManager.CreateTokenRequestSession(tokenRequestHandlerId);

            tokenRequestSession.Scope = allowedScopes;
            tokenRequestSession.IsInLoginSession = false;
            tokenRequestSession.IsOfflineAccess = false;

            _tokenManager.UpdateTokenRequestSession(tokenRequestSession);

            //return tokenRequestSession;
        }

        /// <summary>
        /// TODO: from duende
        /// </summary>
        /// <param name="formPost"></param>
        /// <returns></returns>
        private async Task WriteHtmlAsync(HttpResponse response, string formPost)
        {
            response.ContentType = "text/html; charset=UTF-8";
            await response.WriteAsync(formPost, Encoding.UTF8);
            await response.Body.FlushAsync();
        }


        /// <summary>
        /// From identityserver4
        /// </summary>
        private const string FormPostHtml = "<html><head><meta http-equiv='X-UA-Compatible' content='IE=edge' /><base target='_self'/></head><body><form method='post' action='{uri}'>{body}<noscript><button>Click to continue</button></noscript></form><script>window.addEventListener('load', function(){document.forms[0].submit();});</script></body></html>";

        /// <summary>
        /// From identityserver4
        /// </summary>
        /// <param name="redirectUri"></param>
        /// <param name="inputBody"></param>
        /// <returns></returns>
        private string GetFormPostHtml(string redirectUri, Dictionary<string, string> inputBody)
        {
            var html = FormPostHtml;

            var url = redirectUri;
            url = HtmlEncoder.Default.Encode(url);
            html = html.Replace("{uri}", url);
            html = html.Replace("{body}", ToFormPost(inputBody));

            return html;
        }

        private string ToFormPost(Dictionary<string, string> collection)
        {
            var builder = new StringBuilder(128);
            const string inputFieldFormat = "<input type='hidden' name='{0}' value='{1}' />\n";

            foreach (var keyValue in collection)
            {
                var value = keyValue.Value;
                //var value = value;
                value = HtmlEncoder.Default.Encode(value);
                builder.AppendFormat(inputFieldFormat, keyValue.Key, value);
            }

            return builder.ToString();
        }
        #endregion

        #region Issue token
        [HttpGet("token")]
        [Authorize]
        // 5.3.2.  Successful UserInfo Response: https://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse
        public async Task<ActionResult> TokenEndpointAsync()
        {
            // TODO
            return StatusCode(200);
        }

        // TODO: try to implement from
        //     : https://www.oauth.com/oauth2-servers/making-authenticated-requests/refreshing-an-access-token/
        //     : Token Request Validation: https://openid.net/specs/openid-connect-core-1_0.html
        //     : only allow authorization code to get access token and id token,
        //     : access token will be use for scope uri, like userinfo or email...
        [HttpPost("token")]
        [AllowAnonymous]
        public async Task<ActionResult> TokenEndpointPostAsync()
        {
            // TODO: for now, only response to authorization code request to access token
            //     : need to implement another action
            //     : send back access_token when have request refresh 

            string requestBody = await Utilities.GetRequestBodyAsQueryFormAsync(HttpContext.Request.Body);
            string grantType = await TokenEndpoint_GetGrantTypeAsync(requestBody);

            switch (grantType)
            {
                case OidcConstants.GrantTypes.RefreshToken:
                    {
                        // 1. check token response information.
                        // 2. check request for that response, which it has offline access or not
                        // 3. check expired time of refresh token and access token
                        // 4. issue new access token if there is no problem

                        return await IssueTokenForRefreshToken(requestBody);
                    }
                case OidcConstants.GrantTypes.AuthorizationCode:
                    return await IssueTokenForAuthorizationCodeAsync(requestBody);
                default:
                    return StatusCode((int)HttpStatusCode.NotImplemented, ExceptionMessage.NOT_IMPLEMENTED);
            }
        }

        private static async Task<string> TokenEndpoint_GetGrantTypeAsync(string requestBody)
        {
            return requestBody.Remove(0, 1).Split("&")
                .First(t => t.StartsWith("grant_type"))
                .Replace("grant_type=", "");
        }

        private async Task<ActionResult> IssueTokenForRefreshToken(string requestBody)
        {
            // 1. check refresh token type, external or local
            // 2. if local, check expired time, issue token
            // 3. if external, send request to external source to get response

            OfflineAccessTokenParameters parameters = new OfflineAccessTokenParameters(requestBody);

            var refreshToken = _tokenManager.FindRefreshToken(parameters.RefreshToken.Value);
            ValidateRefreshToken(refreshToken.TokenExpiried);

            string tokenResponses = string.Empty;
            // Token from external source
            if (!string.IsNullOrEmpty(refreshToken.ExternalSource))
            {
                // TODO: will update this part later
                tokenResponses = await _tokenManager.RefreshAccessTokenFromExternalSourceAsync(refreshToken.Token, refreshToken.ExternalSource);
            }
            else
            {
                tokenResponses = await _tokenManager.IssueTokenForRefreshToken(refreshToken);
            }

            return StatusCode((int)HttpStatusCode.OK, tokenResponses);
        }

        private static bool ValidateRefreshToken(DateTime expiredTime)
        {
            if (expiredTime <= DateTime.Now)
                throw new CustomException(ExceptionMessage.REFRESH_TOKEN_EXPIRED, HttpStatusCode.Unauthorized);

            return true;
        }

        private async Task<ActionResult> IssueTokenForAuthorizationCodeAsync(string requestBody)
        {
            // TODO: get from queryString, authorization code
            //     : get user along with authorization code inside latest login session (of that user)
            //     : create access token and id token, send it to client
            AuthCodeTokenParameters parameters = new AuthCodeTokenParameters(requestBody);

            // TODO: for now, every request, by default in scop will have openid, so ignore this part of checking now
            //     : Verify that the Authorization Code used was issued in response to an OpenID Connect Authentication Request(so that an ID Token will be returned from the Token Endpoint).
            var tokenRequestHandler = _tokenManager.FindTokenRequestHandlerByAuthorizationCode(parameters.Code.Value);
            // TODO: will change to use email when allow using identity from another source
            UserIdentity user = ACF_II_GetResourceOwnerIdentity(tokenRequestHandler.User.UserName);
            var client = ACF_II_VerifyAndGetClient(parameters.ClientId.Value, parameters.ClientSecret.Value, tokenRequestHandler);

            ACF_II_VerifyRedirectUris(parameters.RedirectUri.Value, tokenRequestHandler.RequestSession.RedirectUri);
            ACF_II_VerifyCodeChallenger(parameters.CodeVerifier.Value, tokenRequestHandler);

            // TODO: issue token from TokenManager
            var tokenResponses = _tokenManager.ACF_IssueToken(user.Id, client.Id, client.ClientId, tokenRequestHandler.Id);

            SuccessfulRequestHandle(tokenRequestHandler);

            return StatusCode((int)HttpStatusCode.OK, tokenResponses);
        }

        // TODO: will test again
        private UserIdentity ACF_II_GetResourceOwnerIdentity(string userName)
        {
            var obj = _applicationUserManager.Current.Users
                    .Include(u => u.IdentityRequestHandlers)
                    .Include(u => u.IdentityRequestHandlers).ThenInclude(s => s.Client)
                    .Include(u => u.IdentityRequestHandlers).ThenInclude(l => l.RequestSession)
                    .FirstOrDefault(u => u.UserName == userName);
            if (obj == null)
                throw new InvalidDataException(ExceptionMessage.USER_NULL);

            return obj;
        }

        private static void ACF_II_VerifyRedirectUris(string redirectUri, string authRequestRedirectUri)
        {
            //Ensure that the redirect_uri parameter value is identical to the redirect_uri parameter value that was included in the initial Authorization Request.
            //If the redirect_uri parameter value is not present when there is only one registered redirect_uri value,
            //the Authorization Server MAY return an error(since the Client should have included the parameter) or MAY proceed without an error(since OAuth 2.0 permits the parameter to be omitted in this case).

            Uri token_redirectUri = new Uri(redirectUri);
            Uri authCode_redirectUri = new Uri(authRequestRedirectUri);

            if (!ACF_II_RedirectUriIsRegistered(token_redirectUri, authCode_redirectUri))
                throw new CustomException(ExceptionMessage.REDIRECTURI_IS_MISMATCH, HttpStatusCode.BadRequest);
        }

        private static bool ACF_II_RedirectUriIsRegistered(Uri redirectUri, Uri authRequestRedirectUri)
        {
            if (redirectUri.Equals(authRequestRedirectUri))
                return true;
            return false;
        }

        private static void ACF_II_VerifyCodeChallenger(string codeVerifier, IdentityRequestHandler requestHandler)
        {
            // TODO: by default, those two go along together, maybe in different way in future when compare with which is used now
            if (requestHandler.RequestSession.CodeChallenge != null
                && requestHandler.RequestSession.CodeChallengeMethod != null)
            {
                if (requestHandler.RequestSession.CodeChallengeMethod.Equals(CodeChallengeMethods.Plain))
                {
                    if (!codeVerifier.Equals(requestHandler.RequestSession.CodeChallenge))
                        throw new CustomException(ExceptionMessage.CLIENT_OF_TOKEN_REQUEST_IS_DIFFERENT_WITH_AUTH_CODE_REQUEST, HttpStatusCode.BadRequest);
                }
                else if (requestHandler.RequestSession.CodeChallengeMethod.Equals(CodeChallengeMethods.Sha256))
                {
                    var code_challenge = RNGCryptoServicesUltilities.Base64urlencodeNoPadding(codeVerifier.EncodingWithSHA265());
                    if (!code_challenge.Equals(requestHandler.RequestSession.CodeChallenge))
                        throw new CustomException(ExceptionMessage.CLIENT_OF_TOKEN_REQUEST_IS_DIFFERENT_WITH_AUTH_CODE_REQUEST, HttpStatusCode.BadRequest);
                }
                else
                {
                    throw new CustomException(ExceptionMessage.CODE_CHALLENGE_METHOD_NOT_SUPPORT);
                }
                
            }
        }

        // TODO: will test again
        private Client ACF_II_VerifyAndGetClient(string clientId, string clientSecret, IdentityRequestHandler tokenRequestHandler)
        {
            Client client = _clientDbServices.Find(clientId, clientSecret);

            if (tokenRequestHandler.RequestSession != null
                && !tokenRequestHandler.Client.Id.Equals(client.Id))
                // TODO: status code may wrong
                throw new CustomException(ExceptionMessage.CLIENT_OF_TOKEN_REQUEST_IS_DIFFERENT_WITH_AUTH_CODE_REQUEST);

            return client;
        }
        #endregion

        #region UserInfo
        [HttpGet("userinfo")]
        [Authorize]
        public async Task<ActionResult> GetUserInfoAsync()
        {
            // TODO: exchange access token to get user from latest login session inside memory
            //     : create user_info json response to send to client

            // TODO: by using authorization before this part, so it should has an user in HttpContext
            //     : in current context of services, when I use async, this function return an error about "connection is lost"...
            var user = _applicationUserManager.Current.GetUserAsync(HttpContext.User).Result;

            if (user == null)
                throw new InvalidOperationException(ExceptionMessage.OBJECT_NOT_FOUND);

            object responseBody = await ResponseForUserInfoRequestAsync(user);
            // TODO: has some bug inside this function, will fix it later
            //string responseBody = await Utilities.CreateUserInfoResponseAsync(user);

            return StatusCode((int)HttpStatusCode.OK, responseBody);
        }

        private static async Task<object> ResponseForUserInfoRequestAsync(UserIdentity user)
        {
            return new
            {
                sub = user.UserName,
                name = user.FullName,
                email = user.Email,
                email_confirmed = user.EmailConfirmed,
                picture = user.Avatar
            };
        }

        [HttpGet("userinfo.email")]
        [Authorize]
        public async Task<ActionResult> GetUserInfoAndEmailAsync()
        {
            // TODO: exchange access token to get user from latest login session inside memory
            //     : create user_info json response to send to client

            return StatusCode(200);
        }
        #endregion

        #region Google authentication
        //[HttpPost("v{version:apiVersion}/authorize/google")]
        [HttpPost("authorize/google")]
        [AllowAnonymous]
        // TODO: comment for now, but when everything is done, this policy must be used, 
        //     : only identityserver's clients can use this endpoint, not user-agent
        public async Task<ActionResult> GoogleAuthenticating()
        {
            var googleClientConfig = _configuration.GetSection(IdentityServerConfiguration.GOOGLE_CLIENT).Get<GoogleSettings>();
            ValidateGoogleSettings(googleClientConfig);

            string requestQuery = await Utilities.GetRequestBodyAsQueryFormAsync(HttpContext.Request.Body);

            // TODO: add '?' before requestBody to get query form of string
            // , AbtractRequestParamters instances use request query as parameter
            var parameters = new SignInGoogleParameters(requestQuery);

            var client = _clientDbServices.Find(parameters.ClientId.Value, parameters.ClientSecret.Value);

            var result = await GetGoogleInfo(parameters, googleClientConfig);
            // TODO: will learn how to use it, comment for now
            GoogleJsonWebSignature.Payload payload = await GoogleJsonWebSignature.ValidateAsync(result.IdToken);

            string user_info = await userinfoCallAsync(result.AccessToken, googleClientConfig.UserInfoUri);
            // TODO: create new user or map google user infor to current, get unique user by email
            var user = _applicationUserManager.GetOrCreateUserByEmail(payload);

            // TODO: associate google info with current user identity inside database, using email to do it
            //     : priority information inside database, import missing info from google
            var requestHandler = GoogleAuth_ImportRequestHandlerData(parameters.CodeVerifier.Value, result.RefreshToken, client, user);

            // at this step, token request session is used for storing data
            GoogleAuth_SaveToken(result.AccessToken, result.RefreshToken, result.IdToken, 
                payload.IssuedAtTimeSeconds.Value, payload.ExpirationTimeSeconds.Value , result.AccessTokenIssueAt, result.AccessTokenIssueAt.AddSeconds(result.ExpiredIn),
                payload, requestHandler);

            SuccessfulRequestHandle(requestHandler);
            var response = await Utilities.CreateTokenResponseStringAsync(result.AccessToken, result.IdToken, Utilities.Google_TimeSecondsToDateTime(payload.ExpirationTimeSeconds.Value), ExternalSources.Google, string.IsNullOrEmpty(result.RefreshToken) ? "" : result.RefreshToken);
            // TODO: will need to create new user if current user with this email is not have
            //     : after that, create login session object and save to db
            //     : after create login session, authentication then will perform
            return Ok(response);
        }

        private bool GoogleAuth_SaveToken(string accessToken, string refreshToken, string idToken, 
            long issuedAtTimeSeconds, long expirationTimeSeconds, DateTime accessTokenIssueAt, DateTime accessTokenExpiredIn,
            GoogleJsonWebSignature.Payload payload, IdentityRequestHandler requestHandler)
        {
            return _tokenManager.SaveTokenFromExternalSource(accessToken, refreshToken, idToken, 
                issuedAtTimeSeconds, expirationTimeSeconds, accessTokenIssueAt, accessTokenExpiredIn,
                requestHandler, ExternalSources.Google);
        }

        private IdentityRequestHandler GoogleAuth_ImportRequestHandlerData(string codeVerifier, string refreshToken, Client client, UserIdentity user)
        {
            var requestHandler = _tokenManager.GetDraftTokenRequestHandler();
            requestHandler.User = user;
            requestHandler.Client = client;

            _tokenManager.UpdateTokenRequestHandler(requestHandler);

            GoogleAuth_CreateRequestSession(codeVerifier, refreshToken, requestHandler);

            return requestHandler;
        }

        private void GoogleAuth_CreateRequestSession(string codeVerifier, string refreshToken, IdentityRequestHandler requestHandler)
        {
            var session = _tokenManager.CreateTokenRequestSession(requestHandler.Id);
            session.CodeVerifier = codeVerifier;
            session.IsOfflineAccess = string.IsNullOrEmpty(refreshToken) ? false : true;

            _tokenManager.UpdateTokenRequestSession(session);
        }

        private async Task<(string AccessToken, string IdToken, string RefreshToken, DateTime AccessTokenIssueAt, double ExpiredIn)> GetGoogleInfo(SignInGoogleParameters parameters, GoogleSettings config)
        {
            // builds the request
            string tokenRequestBody = string.Format("code={0}&redirect_uri={1}&client_id={2}&code_verifier={3}&client_secret={4}&scope=&grant_type=authorization_code",
                parameters.AuthorizationCode.Value,
                parameters.RedirectUri.Value,
                config.ClientId,
                parameters.CodeVerifier.Value,
                config.ClientSecret);

            // sends the request
            HttpWebRequest tokenRequest = (HttpWebRequest)WebRequest.Create(config.TokenUri);
            tokenRequest.Method = "POST";
            tokenRequest.ContentType = "application/x-www-form-urlencoded";
            tokenRequest.Accept = "Accept=text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
            byte[] _byteVersion = Encoding.ASCII.GetBytes(tokenRequestBody);
            tokenRequest.ContentLength = _byteVersion.Length;
            Stream stream = tokenRequest.GetRequestStream();
            await stream.WriteAsync(_byteVersion, 0, _byteVersion.Length);
            stream.Close();

            string id_token = "";
            string access_token = "";
            string refresh_token = "";
            double expired_in = default;
            DateTime accessTokenIssueAt;

            // gets the response
            WebResponse tokenResponse = await tokenRequest.GetResponseAsync();
            using (StreamReader reader = new StreamReader(tokenResponse.GetResponseStream()))
            {
                // reads response body
                string responseText = await reader.ReadToEndAsync();

                // converts to dictionary
                Dictionary<string, string> result = JsonConvert.DeserializeObject<Dictionary<string, string>>(responseText);

                access_token = result["access_token"];
                id_token = result["id_token"];
                result.TryGetValue("refresh_token", out refresh_token);
                result.TryGetValue("expires_in", out string temp);

                expired_in = double.Parse($"{temp}");
                accessTokenIssueAt = DateTime.Now;
                // TODO: validate at_hash from id_token is OPTIONAL in some flows (hybrid flow,...),
                //     : I will check when to implement it later, now, better it has than it doesn't
                //     : comment for now
                //ValidateAtHash(id_token, access_token);
            }

            return new(access_token, id_token, refresh_token, accessTokenIssueAt, expired_in);
        }

        private static void ValidateGoogleSettings(GoogleSettings? googleClientConfig)
        {
            if (googleClientConfig == null)
                throw new CustomException("Elaboration of google inside server is mismatch!");

            if (googleClientConfig == null
                || string.IsNullOrEmpty(googleClientConfig.ClientId)
                || string.IsNullOrEmpty(googleClientConfig.ClientSecret)
                || string.IsNullOrEmpty(googleClientConfig.AuthUri)
                || string.IsNullOrEmpty(googleClientConfig.TokenUri)
                || googleClientConfig.RedirectUris == null || googleClientConfig.RedirectUris.Count == 0)
                throw new CustomException("Elaboration of google inside server is mismatch!");
        }

        /// <summary>
        /// TODO: validate at_hash from id_token is OPTIONAL in some flow,
        ///     : I will check when to implement it later, now, better it has than it doesn't
        ///     https://openid.net/specs/openid-connect-core-1_0.html#FormSerialization
        ///     and https://stackoverflow.com/questions/30356460/how-do-i-validate-an-access-token-using-the-at-hash-claim-of-an-id-token
        /// </summary>
        /// <param name="id_token"></param>
        /// <param name="access_token"></param>
        private bool ValidateAtHash(string id_token, string access_token)
        {
            JwtSecurityToken idTokenAsClaims = DecodeIdTokenString(id_token);

            var alg = idTokenAsClaims.Header["alg"];
            var at_hash = idTokenAsClaims.Claims.FirstOrDefault(c => c.Type.Equals("at_hash"));
            if (alg.Equals(SecurityAlgorithms.RsaSha256))
            {
                if (at_hash != null && at_hash.Value != null)
                {
                    // TODO: verify access token
                    using (SHA256 hashProtocol = SHA256.Create())
                    {
                        byte[] accessTokenAsEncodeBytes = hashProtocol.ComputeHash(Encoding.ASCII.GetBytes(access_token));
                        byte[] firstHalf = accessTokenAsEncodeBytes.Take(accessTokenAsEncodeBytes.Length / 2).ToArray();

                        var checkPoint = RNGCryptoServicesUltilities.Base64urlencodeNoPadding(firstHalf);

                        return at_hash.Value.Equals(checkPoint);
                    }
                }
            }

            return false;
        }

        private JwtSecurityToken DecodeIdTokenString(string id_token)
        {
            var handler = new JwtSecurityTokenHandler();
            var jwtSecurityToken = handler.ReadJwtToken(id_token);
            return jwtSecurityToken;
        }

        private async Task<string> userinfoCallAsync(string access_token, string userInfoUri)
        {
            string userInfo = "";

            // sends the request
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(userInfoUri);
            request.Method = "GET";
            request.Headers.Add(string.Format("Authorization: Bearer {0}", access_token));
            request.ContentType = "application/x-www-form-urlencoded";
            request.Accept = "Accept=text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";

            // gets the response
            WebResponse response = await request.GetResponseAsync();
            using (StreamReader reader = new StreamReader(response.GetResponseStream()))
            {
                // reads response body
                string result = await reader.ReadToEndAsync();
                userInfo = result;
            }

            return userInfo;
        }
        #endregion

        #region DiscoveryWebKeys
        [HttpGet("jwks")]
        [AllowAnonymous]
        public ActionResult GetPublicKeyForVerifyingIdToken()
        {
            var publicKey = _tokenManager.GetPublicKeyJson();

            return StatusCode((int)HttpStatusCode.OK, JsonConvert.SerializeObject(publicKey, Formatting.Indented));
        }
        #endregion

        #region sharing functions
        private void SuccessfulRequestHandle(IdentityRequestHandler requestHandler)
        {
            requestHandler.SuccessAt = DateTime.UtcNow;
            _tokenManager.UpdateTokenRequestHandler(requestHandler);
        }
        #endregion
    }
}
