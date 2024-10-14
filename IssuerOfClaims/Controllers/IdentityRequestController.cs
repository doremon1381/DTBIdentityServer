using IssuerOfClaims.Controllers.Ultility;
using ServerUltilities.Extensions;
using MimeKit;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Newtonsoft.Json;
using ServerDbModels;
using ServerUltilities;
using ServerUltilities.Identity;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Web;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using IssuerOfClaims.Services.Database;
using IssuerOfClaims.Extensions;
using IssuerOfClaims.Services.Token;
using static ServerUltilities.Identity.OidcConstants;
using IssuerOfClaims.Services;
using Microsoft.IdentityModel.Tokens;
using static ServerUltilities.Identity.Constants;
using System.Reflection;
using IssuerOfClaims.Models;
using Azure.Core;
using Google.Apis.Auth;
using Microsoft.AspNetCore.Http;
using IssuerOfClaims.Models.Request;

namespace IssuerOfClaims.Controllers
{
    [ApiController]
    [Route("[controller]")]
    //[ApiVersion("1.0")]
    [ControllerName("oauth2")]
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
            try
            {
                // 1. Get authorization request from server
                // 2. Return an http 302 message to server, give it a nonce cookie (for now, ignore this part),
                //    if asking for google, then send a redirect to google to get authorization code
                //    if basic access (I mean implicit grant - form_post or not), then return a redirect to another request to identity server - send request to "authentication/basicAccess" route
                // 3.

                AuthCodeParameters parameters = new AuthCodeParameters(HttpContext.Request.QueryString.Value);

                var client = _clientDbServices.Find(parameters.ClientId.Value);

                ACF_VerifyClient(client);
                ACF_VerifyRedirectUris(parameters, client);

                switch (parameters.ResponseType.Value)
                {
                    case ResponseTypes.Code:
                        return await IssueAuthorizationCodeAsync(parameters);
                    case ResponseTypes.IdToken:
                        return await ImplicitGrantWithFormPostAsync(parameters);
                    case ResponseTypes.IdTokenToken:
                        throw new CustomException((int)HttpStatusCode.NotImplemented, "Not yet implement!");
                    // TODO: will implement another flow if I have time
                    default:
                        throw new CustomException((int)HttpStatusCode.NotImplemented, "Not yet implement!");
                }
            }
            catch (CustomException ex)
            {
                // TODO: will check again
                return StatusCode(ex.ExceptionIssueToward.Equals(ExceptionIssueToward.UserAgent) ? ex.StatusCode : (int)HttpStatusCode.InternalServerError, ex.Message);
            }
            catch (Exception ex)
            {
                throw;
            }
        }

        private void ACF_VerifyClient(Client client)
        {
            if (client == null || client.Id == 0)
                throw new InvalidOperationException("client id is wrong!");
        }

        private void ACF_VerifyRedirectUris(AuthCodeParameters parameters, Client client)
        {
            string[] redirectUris = client.RedirectUris.Split(",");
            if (!redirectUris.Contains(parameters.RedirectUri.Value))
                throw new InvalidOperationException("redirectUri is mismatch!");
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
        private async Task<ActionResult> IssueAuthorizationCodeAsync(AuthCodeParameters parameters)
        {
            // TODO: comment for now
            //     : by using AuthenticateHanlder, in this step, authenticated is done
            //     : get user, create authorization code, save it to login session and out

            UserIdentity user = await ACF_I_GetResourceOwnerIdentity();
            var client = _clientDbServices.Find(parameters.ClientId.Value);

            ACF_I_VerifyClient(parameters.Scope.Value, client);

            var acfProcessSession = _tokenManager.CreateTokenRequestSession();
            ACF_I_UpdateRequestSessionDetails(parameters, acfProcessSession, client, out string authorizationCode);
            ACF_I_CreateTokenRequestHandler(user, acfProcessSession);

            #region TODO: using these statements because has an error with tracking object, for now i dont know why 
            var requestSession = _tokenManager.FindRequestSessionById(acfProcessSession.Id);
            requestSession.Client = client;
            _tokenManager.UpdateTokenRequestSession(requestSession);
            #endregion

            // TODO: for now, explicit use response type will have no meaning, but I will think about how to handle response type later
            // Create a custom response object
            object responseBody = new
            {
                state = parameters.State.Value,
                code = authorizationCode
            };

            // TODO: comment for now
            //ACF_I_AddResponseStatus(200);

            // TODO: if following openid specs, I will need to return responseBody as query or fragment inside uri
            //     , but currently I don't know particular form of the response
            //     , so if it 's considered a bug, I will fix it later
            return StatusCode((int)HttpStatusCode.OK, System.Text.Json.JsonSerializer.Serialize(responseBody));
        }

        private async Task<UserIdentity> ACF_I_GetResourceOwnerIdentity()
        {
            var obj = await _applicationUserManager.Current.GetUserAsync(HttpContext.User);

            if (obj == null)
                throw new InvalidDataException(ExceptionMessage.USER_NULL);

            return obj;
        }

        private void ACF_I_AddResponseStatus(int statusCode)
        {
            // TODO: change for now
            HttpContext.Response.StatusCode = statusCode;
            // TODO: has error
            //HttpContext.Response.Headers.Append("state", state);

            // TODO: I don't know why if add "Location" as key in response header, the response will be sent to vuejs's web is with status code 200,
            //     : but if I modify the name, for example, to "Location1", then the response will has status code 302 as I set to it before...
            //HttpContext.Response.Headers.Append("location", string.Format("{0}?code={1}", redirectUri, authorizationCode));
        }

        private void ACF_I_VerifyClient(string scopes, Client client)
        {
            if (client.Id == 0)
                throw new InvalidDataException(ExceptionMessage.INVALID_CLIENTID);
            if (!ACF_I_IsSimilarWithClientScopes(scopes, client))
                throw new InvalidDataException(ExceptionMessage.SCOPES_NOT_ALLOWED);
        }
        private bool ACF_I_IsSimilarWithClientScopes(string scopes, Client client)
        {
            var variables = System.Uri.UnescapeDataString(scopes).Split(" ");
            foreach (var s in variables)
            {
                if (!client.AllowedScopes.Contains(s))
                    return false;
            }
            return true;
        }
        /// <summary>
        /// TODO: will fix some error when adding transient or scopped dbcontext
        /// </summary>
        /// <param name="user"></param>
        /// <param name="ACFProcessSession"></param>
        private TokenRequestHandler ACF_I_CreateTokenRequestHandler(UserIdentity user, TokenRequestSession ACFProcessSession)
        {
            var tokenRequestHandler = _tokenManager.GetDraftTokenRequestHandler();
            tokenRequestHandler.User = user;
            tokenRequestHandler.TokenRequestSession = ACFProcessSession;

            // TODO: will check again
            _tokenManager.UpdateTokenRequestHandler(tokenRequestHandler);

            return tokenRequestHandler;
        }
        private void ACF_I_UpdateRequestSessionDetails(AuthCodeParameters parameters, TokenRequestSession ACFProcessSession, Client client, out string authorizationCode)
        {
            ACF_I_ImportPKCERequestedParams(parameters.CodeChallenge.Value, parameters.CodeChallengeMethod.Value, parameters.CodeChallenge.HasValue, ACFProcessSession);
            ACF_I_ImportRequestSessionData(parameters.Scope.Value, parameters.Nonce.Value, ACFProcessSession, out authorizationCode);
        }
        private void ACF_I_ImportRequestSessionData(string scope, string nonce, TokenRequestSession tokenRequestSession, out string authorizationCode)
        {
            // TODO: create authorization code
            authorizationCode = RNGCryptoServicesUltilities.RandomStringGeneratingWithLength(32);

            tokenRequestSession.AuthorizationCode = authorizationCode;
            tokenRequestSession.Nonce = nonce;
            tokenRequestSession.Scope = scope;
            tokenRequestSession.IsOfflineAccess = scope.Contains(StandardScopes.OfflineAccess);
            _tokenManager.UpdateTokenRequestSession(tokenRequestSession);
        }
        private void ACF_I_ImportPKCERequestedParams(string codeChallenge, string codeChallengeMethod, bool codeChallenge_HasValue, TokenRequestSession tokenRequestSession)
        {
            if (codeChallenge_HasValue)
            {
                tokenRequestSession.CodeChallenge = codeChallenge;
                tokenRequestSession.CodeChallengeMethod = codeChallengeMethod;
            }
        }
        #endregion

        #region resiger user
        // TODO: by default, I seperate the need of creating identity of someone with the flow of oauth2's authorization code flow 
        //     : but following specs, my implement maybe wrong, but I know it is optional or "more guideline" than "actual rules"
        [HttpPost("register")]
        //[Authorize]
        public async Task<ActionResult> RegisterIdentity()
        {
            try
            {
                RegisterParameters parameters = new RegisterParameters(HttpContext.Request.QueryString.Value, HttpContext.Request.Headers);

                ValidateRedirectUri(parameters);

                return await RegisterUserAsync(parameters);
            }
            catch (CustomException ex)
            {
                // TODO: will check again
                return StatusCode(ex.ExceptionIssueToward.Equals(ExceptionIssueToward.UserAgent) ? ex.StatusCode : (int)HttpStatusCode.InternalServerError, ex.Message);
            }
            catch (Exception ex)
            {
                // TODO: will check again
                _logger.LogError($"REGISTER ENDPOINT: {ex.Message}");
                throw;
            }
        }

        private Client GetClient(string clientId)
        {
            var client = _clientDbServices.Find(clientId);
            if (client == null || client.Id == 0)
                throw new InvalidDataException("client id is wrong!");

            return client;
        }

        private void ValidateRedirectUri(RegisterParameters parameters)
        {
            Client client = GetClient(parameters.ClientId.Value);

            string[] redirectUris = client.RedirectUris.Split(",");
            if (!redirectUris.Contains(parameters.RedirectUri.Value))
                throw new InvalidDataException("redirectUri is mismatch!");
        }

        public async Task<ActionResult> RegisterUserAsync(RegisterParameters parameters)
        {
            // TODO: will add role later
            // TODO: for now, I allow one email can be used by more than one UserIdentity
            //     : but will change to "one email belong to one useridentity" later
            VerifyUser(parameters.UserName.Value, parameters.Email.Value);

            // TODO: will check again
            var user = _applicationUserManager.CreateUser(parameters);

            // TODO: https://openid.net/specs/openid-connect-prompt-create-1_0.html#name-authorization-request
            var client = _clientDbServices.Find(parameters.ClientId.Value);

            // TODO: will check again
            string id_token = _tokenManager.GenerateIdTokenAndRsaSha256PublicKey(user, string.Empty, parameters.Nonce.Value, client.ClientId)
                .Cast(new { IdToken = string.Empty, PublicKey = new object() })
                .IdToken;

            if (parameters.Email.HasValue)
                await _emailServices.SendVerifyingEmailAsync(user, "ConfirmEmail", client, Request.Scheme, Request.Host.ToString());

            object responseBody = CreateRegisterUserResponseBody(id_token, parameters.State.Value, parameters.State.HasValue);

            return StatusCode((int)HttpStatusCode.OK, responseBody);
        }

        private void VerifyUser(string userName, string email)
        {
            if (_applicationUserManager.EmailIsUsedForUser(email) 
                || _applicationUserManager.HasUser(userName))
                throw new CustomException((int)HttpStatusCode.Conflict, ExceptionMessage.USER_ALREADY_EXISTS);
        }

        private static object CreateRegisterUserResponseBody(string id_token, string state = "", bool stateHasValue = false)
        {
            object responseBody = new
            {
                status = 200,
                message = "new user is created!",
                id_token = id_token
            };

            if (stateHasValue)
            {
                responseBody = new
                {
                    status = 200,
                    message = "new user is created!",
                    state = state,
                    id_token = id_token
                };
            }

            return responseBody;
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
        private async Task<ActionResult> ImplicitGrantWithFormPostAsync(AuthCodeParameters parameters)
        {
            try
            {
                // TODO: for this situation, Thread and http context may not need
                //var principal = Thread.CurrentPrincipal;
                var principal = HttpContext.User;

                var user = await _applicationUserManager.Current.GetUserAsync(principal);
                var client = _clientDbServices.Find(parameters.ClientId.Value);

                // TODO: scope is used for getting claims to send to client,
                //     : for example, if scope is missing email, then in id_token which will be sent to client will not contain email's information 
                var idToken = _tokenManager.GenerateIdTokenAndRsaSha256PublicKey(user, parameters.Scope.Value, parameters.Nonce.Value, client.ClientId)
                    .Cast(new { IdToken = string.Empty, PublicKey = new object() })
                    .IdToken;

                //var tokenResponse = _tokenManager.GenerateIdToken();

                // TODO: update must follow order, I will explain late
                //IGF_UpdateTokenResponse(idToken, tokenResponse);
                IGF_UpdateTokenRequestHandler(user, client, idToken);

                // Check response mode to know what kind of response is going to be used
                // return a form_post, url fragment or body of response
                if (parameters.ResponseMode.Value.Equals(ResponseModes.FormPost))
                {
                    Dictionary<string, string> inputBody = new Dictionary<string, string>();
                    inputBody.Add(AuthorizeResponse.IdentityToken, idToken);

                    //string formPost = GetFormPostHtml(webServerConfiguration["redirect_uris:0"], inputBody);
                    string formPost = GetFormPostHtml(parameters.RedirectUri.Value, inputBody);

                    HttpContext.Response.Headers.Append("state", parameters.State.Value);

                    // TODO: will learn how to use this function
                    await WriteHtmlAsync(HttpContext.Response, formPost);

                    // TODO: will learn how to use it later
                    return new EmptyResult();
                }
                else if (parameters.ResponseMode.Value.Equals(ResponseModes.Fragment))
                {
                    // TODO:
                }
                else if (parameters.ResponseMode.Value.Equals(ResponseModes.Query))
                {
                    // TODO: will need to add state into response, return this form for now
                    return StatusCode((int)HttpStatusCode.OK, idToken);
                }
                else
                    return StatusCode((int)HttpStatusCode.BadRequest, "Response mode is not allowed!");

            }
            catch (Exception ex)
            {
                return StatusCode((int)HttpStatusCode.InternalServerError, ex.Message);
            }


            return StatusCode((int)HttpStatusCode.OK, "every thing is done!");
        }

        private void IGF_UpdateTokenRequestHandler(UserIdentity user, Client client, string idToken)
        {
            //var tokenRequestHandler = _tokenRequestHandlerDbServices.GetDraftObject();
            //var tokenRequestSession = IGF_CreateRequestSession(client);

            //tokenRequestHandler.User = user;
            //tokenRequestHandler.TokenRequestSession = tokenRequestSession;

            //// TODO: need to add id token to this part

            //_tokenRequestHandlerDbServices.Update(tokenRequestHandler);
        }

        private void IGF_UpdateTokenResponse(string idToken, ServerDbModels.TokenResponse tokenResponse)
        {
            // TODO
            //tokenResponse.IdToken = idToken;

            //_tokenResponseDbServices.Update(tokenResponse);
        }

        //private TokenRequestSession IGF_CreateRequestSession(Client client)
        //{
        //    var tokenRequestSession = _tokenRequestSessionDbServices.CreateTokenRequestSession();

        //    tokenRequestSession.Client = client;
        //    tokenRequestSession.Scope = client.AllowedScopes;
        //    tokenRequestSession.IsInLoginSession = false;
        //    tokenRequestSession.IsOfflineAccess = false;

        //    _tokenRequestSessionDbServices.Update(tokenRequestSession);

        //    return tokenRequestSession;
        //}

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
            try
            {
                // TODO: for now, only response to authorization code request to access token
                //     : need to implement another action
                //     : send back access_token when have request refresh 

                string requestBody = await GetRequestBodyAsQueryFormAsync(HttpContext.Request.Body);
                string grantType = TokenEndpoint_GetGrantType(requestBody);

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
                        return StatusCode((int)HttpStatusCode.InternalServerError, "Unknown error!");
                }
            }
            catch (CustomException ex)
            {
                // TODO: will check again
                return StatusCode(ex.ExceptionIssueToward.Equals(ExceptionIssueToward.UserAgent) ? ex.StatusCode : (int)HttpStatusCode.InternalServerError, ex.Message);
            }
            catch (Exception ex)
            {
                throw;
            }
        }

        private static string TokenEndpoint_GetGrantType(string requestBody)
        {
            return requestBody.Remove(0, 1).Split("&")
                .First(t => t.StartsWith("grant_type"))
                .Replace("grant_type=", "");
        }

        /// <summary>
        /// get parameter from HttpContext.Request.Body
        /// </summary>
        /// <param name="stream">HttpContext.Request.Body</param>
        /// <returns></returns>
        /// <exception cref="InvalidDataException"></exception>
        private static async Task<string> GetRequestBodyAsQueryFormAsync(Stream stream)
        {
            string content = "";
            using (StreamReader reader = new StreamReader(stream))
            {
                content = await reader.ReadToEndAsync();
                // TODO: add '?' to match request query form
                content = "?" + content;
            }

            if (string.IsNullOrEmpty(content))
                throw new InvalidDataException(ExceptionMessage.REQUEST_BODY_NOT_NULL_OR_EMPTY);

            return content;
        }

        private async Task<ActionResult> IssueTokenForRefreshToken(string requestBody)
        {
            // 1. check refresh token type, external or local
            // 2. if local, check expired time, issue token
            // 3. if external, send request to external source to get response

            OfflineAccessTokenParameters parameters = new OfflineAccessTokenParameters(requestBody);

            var refreshToken = _tokenManager.FindRefreshToken(parameters.RefreshToken.Value);

            object tokenResponses = new object();
            // Token from external source
            if (string.IsNullOrEmpty(refreshToken.ExternalSource))
            {
                // TODO: will update this part later
                //var token = refreshToken.ExternalSource switch
                //{
                //    ExternalSources.Google => 
                //    _ => throw new NullReferenceException()
                //};
            }
            else
            {
                tokenResponses = _tokenManager.IssueTokenForRefreshToken(refreshToken);
            }

            return StatusCode((int)HttpStatusCode.OK, System.Text.Json.JsonSerializer.Serialize(tokenResponses));
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

            ACF_II_VerifyRedirectUris(parameters.RedirectUri.Value, client);
            ACF_II_VerifyCodeChallenger(parameters.CodeVerifier.Value, tokenRequestHandler);

            // TODO: issue token from TokenManager
            var tokenResponses = _tokenManager.ACF_IssueToken(user, client, tokenRequestHandler.Id);

            ACF_II_SuccessfulRequestHandle(tokenRequestHandler);

            return StatusCode((int)HttpStatusCode.OK, System.Text.Json.JsonSerializer.Serialize(tokenResponses));
        }

        private void ACF_II_SuccessfulRequestHandle(TokenRequestHandler tokenRequestHandler)
        {
            // TODO: will test again
            tokenRequestHandler.SuccessAt = DateTime.Now;
            _tokenManager.UpdateTokenRequestHandler(tokenRequestHandler);
        }

        private UserIdentity ACF_II_GetResourceOwnerIdentity(string userName)
        {
            var obj = _applicationUserManager.Current.Users
                    .Include(u => u.TokenRequestHandlers)
                    .Include(u => u.TokenRequestHandlers).ThenInclude(l => l.TokenRequestSession).ThenInclude(s => s.Client)
                    .FirstOrDefault(u => u.UserName == userName);
            if (obj == null)
                throw new InvalidDataException(ExceptionMessage.USER_NULL);

            return obj;
        }

        private static void ACF_II_VerifyRedirectUris(string redirectUri, Client client)
        {
            //Ensure that the redirect_uri parameter value is identical to the redirect_uri parameter value that was included in the initial Authorization Request.
            //If the redirect_uri parameter value is not present when there is only one registered redirect_uri value,
            //the Authorization Server MAY return an error(since the Client should have included the parameter) or MAY proceed without an error(since OAuth 2.0 permits the parameter to be omitted in this case).

            string[] redirectUris = client.RedirectUris.Split(",");

            if (!redirectUris.Contains(redirectUri))
                throw new CustomException((int)HttpStatusCode.BadRequest, "redirect_uri is mismatch!");
        }

        private static void ACF_II_VerifyCodeChallenger(string codeVerifier, TokenRequestHandler tokenRequestHandler)
        {
            // TODO: by default, those two go along together, it may wrong in future coding
            if (tokenRequestHandler.TokenRequestSession.CodeChallenge != null
                && tokenRequestHandler.TokenRequestSession.CodeChallengeMethod != null)
            {
                var code_challenge = RNGCryptoServicesUltilities.Base64urlencodeNoPadding(codeVerifier.EncodingWithSHA265());
                if (!code_challenge.Equals(tokenRequestHandler.TokenRequestSession.CodeChallenge))
                    throw new InvalidOperationException("code verifier is wrong!");
            }
        }

        private Client ACF_II_VerifyAndGetClient(string clientId, string clientSecret, TokenRequestHandler tokenRequestHandler)
        {
            Client client = _clientDbServices.Find(clientId, clientSecret);

            if (tokenRequestHandler.TokenRequestSession != null
                && !tokenRequestHandler.TokenRequestSession.Client.Id.Equals(client.Id))
                // TODO: status code may wrong
                throw new InvalidOperationException("something wrong with client which Authorization Code was issued to!");

            return client;
        }

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

            object responseBody = ResponseForUserInfoRequest(user);

            return StatusCode((int)HttpStatusCode.OK, JsonConvert.SerializeObject(responseBody));
        }

        private static object ResponseForUserInfoRequest(UserIdentity user)
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

        #region confirm email after creating user
        /// <summary>
        /// TODO: will verify this function later
        /// </summary>
        /// <returns></returns>
        [HttpGet("ConfirmEmail")]
        [AllowAnonymous]
        public ActionResult CreatingUserConfirm()
        {
            try
            {
                if (!HttpContext.Request.QueryString.HasValue)
                    return StatusCode(400, "query_string_is_mismatch!");

                var query = HttpContext.Request.Query;
                var userId = int.Parse(query["userId"]);
                var code = query["code"];

                // TODO:
                var user = _applicationUserManager.Current.Users.Include(u => u.ConfirmEmails).FirstOrDefault(u => u.Id == userId);
                var createUserConfirmEmail = user.ConfirmEmails.First(e => e.Purpose == (int)ConfirmEmailPurpose.CreateIdentity);

                if (!createUserConfirmEmail.ConfirmCode.Equals(code))
                    return StatusCode(404, "Confirm code is not match!");
                if (!(createUserConfirmEmail.ExpiryTime > DateTime.Now))
                    return StatusCode(400, "Confirm code is expired!");
                if (createUserConfirmEmail.IsConfirmed == true)
                    return StatusCode(200, "Email is confirmed!");
                else
                {
                    user.EmailConfirmed = true;
                    createUserConfirmEmail.IsConfirmed = true;
                }

                var temp = _applicationUserManager.Current.UpdateAsync(user).Result;
            }
            catch (Exception ex)
            {
                return StatusCode(500, ex.Message);
            }
            return StatusCode(200, "Email is confirmed!");
        }
        #endregion

        #region Google authentication
        //[HttpPost("v{version:apiVersion}/authorize/google")]
        [HttpPost("authorize/google")]
        [AllowAnonymous]
        // TODO: comment for now, but when everything is done, this policy must be used, 
        //     : only identityserver's clients can use this endpoint, not user-agent
        //[Authorize(Roles = "Client")]
        public async Task<ActionResult> GoogleAuthenticating()
        {
            try
            {
                var googleClientConfig = _configuration.GetSection(IdentityServerConfiguration.GOOGLE_CLIENT).Get<GoogleSettings>();
                ValidateGoogleSettings(googleClientConfig);

                string requestQuery = await GetRequestBodyAsQueryFormAsync(HttpContext.Request.Body);

                // TODO: add '?' before requestBody to get query form of string
                // , AbtractRequestParamters instances use request query as parameter
                var parameters = new SignInGoogleParameters(requestQuery);

                // at this step, token request session is used for storing data
                var client = _clientDbServices.Find(parameters.ClientId.Value, parameters.ClientSecret.Value);

                // TODO: associate google info with current user identity inside database, using email to do it
                //     : priority information inside database, import missing info from google

                var result = await GetGoogleInfo(parameters, googleClientConfig);
                var resultAfterCast = result.Cast(new { AccessToken = "", IdToken = "", RefreshToken = "", AccessTokenIssueAt = DateTime.Now });
                // TODO: will learn how to use it, comment for now
                GoogleJsonWebSignature.Payload payload = await GoogleJsonWebSignature.ValidateAsync(resultAfterCast.IdToken);

                string user_info = await userinfoCallAsync(resultAfterCast.AccessToken);
                // TODO: create new user or map google user infor to current
                //var email = payload.Email;
                var user = _applicationUserManager.GetOrCreateUserByEmail(payload);
                //user.Avatar = payload.Picture;
                // TODO: get unique user by email

                var requestHandler = GoogleAuth_ImportRequestHandlerData(parameters.CodeVerifier.Value, resultAfterCast.RefreshToken, client, user);

                GoogleAuth_SaveToken(resultAfterCast.AccessToken, resultAfterCast.RefreshToken, resultAfterCast.IdToken, payload.IssuedAtTimeSeconds.Value, payload.ExpirationTimeSeconds.Value
                    , resultAfterCast.AccessTokenIssueAt, payload, requestHandler);

                GoogleAuth_SuccessfulRequestHandle(requestHandler);

                // TODO: will need to create new user if current user with this email is not have
                //     : after that, create login session object and save to db
                //     : after create login session, authentication then will perform
                return Ok(JsonConvert.SerializeObject(user_info, Formatting.Indented));
            }
            catch (CustomException ex)
            {
                // TODO: will check again
                return StatusCode(ex.ExceptionIssueToward.Equals(ExceptionIssueToward.UserAgent) ? ex.StatusCode : (int)HttpStatusCode.InternalServerError, ex.Message);
            }
            catch (Exception ex)
            {
                throw;
            }
        }

        private void GoogleAuth_SuccessfulRequestHandle(TokenRequestHandler requestHandler)
        {
            requestHandler.SuccessAt = DateTime.UtcNow;
            _tokenManager.UpdateTokenRequestHandler(requestHandler);
        }

        private bool GoogleAuth_SaveToken(string accessToken, string refreshToken, string idToken, long issuedAtTimeSeconds, long expirationTimeSeconds, DateTime accessTokenIssueAt, GoogleJsonWebSignature.Payload payload, TokenRequestHandler requestHandler)
        {
            return _tokenManager.SaveTokenFromExternalSource(accessToken, refreshToken, idToken, issuedAtTimeSeconds, expirationTimeSeconds, accessTokenIssueAt, requestHandler, ExternalSources.Google);
        }

        private TokenRequestHandler GoogleAuth_ImportRequestHandlerData(string codeVerifier, string refreshToken, Client client, UserIdentity user)
        {
            var requestHandler = _tokenManager.GetDraftTokenRequestHandler();
            TokenRequestSession session = GoogleAuth_CreateRequestSession(codeVerifier, refreshToken, client);

            requestHandler.TokenRequestSession = session;
            requestHandler.User = user;
            _tokenManager.UpdateTokenRequestHandler(requestHandler);

            return requestHandler;
        }

        private TokenRequestSession GoogleAuth_CreateRequestSession(string codeVerifier, string refreshToken, Client client)
        {
            var session = _tokenManager.CreateTokenRequestSession();
            session.CodeVerifier = codeVerifier;
            session.IsOfflineAccess = string.IsNullOrEmpty(refreshToken) ? false : true;
            session.Client = client;

            _tokenManager.UpdateTokenRequestSession(session);
            return session;
        }

        private async Task<object> GetGoogleInfo(SignInGoogleParameters signInGoogleParameters, GoogleSettings config)
        {
            // builds the request
            string tokenRequestBody = string.Format("code={0}&redirect_uri={1}&client_id={2}&code_verifier={3}&client_secret={4}&scope=&grant_type=authorization_code",
                signInGoogleParameters.AuthorizationCode.Value,
                signInGoogleParameters.RedirectUri.Value,
                config.ClientId,
                signInGoogleParameters.CodeVerifier.Value,
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
                result.TryGetValue("refreshToken", out refresh_token);
                result.TryGetValue("expires_in", out string expiredIn);

                accessTokenIssueAt = DateTime.Now.AddMilliseconds(double.Parse($"-{expiredIn}"));
                // TODO: validate at_hash from id_token is OPTIONAL in some flows (hybrid flow,...),
                //     : I will check when to implement it later, now, better it has than it doesn't
                //     : comment for now
                //ValidateAtHash(id_token, access_token);
            }

            return new { AccessToken = access_token, IdToken = id_token, RefreshToken = refresh_token, AccessTokenIssueAt = accessTokenIssueAt };
        }

        private static void ValidateGoogleSettings(GoogleSettings? googleClientConfig)
        {
            if (googleClientConfig == null)
                throw new CustomException((int)HttpStatusCode.InternalServerError, "Elaboration of google inside server is mismatch!");

            if (googleClientConfig == null
                || string.IsNullOrEmpty(googleClientConfig.ClientId)
                || string.IsNullOrEmpty(googleClientConfig.ClientSecret)
                || string.IsNullOrEmpty(googleClientConfig.AuthUri)
                || string.IsNullOrEmpty(googleClientConfig.TokenUri)
                || googleClientConfig.RedirectUris == null || googleClientConfig.RedirectUris.Count == 0)
                throw new CustomException((int)HttpStatusCode.InternalServerError, "Elaboration of google inside server is mismatch!");
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

        private async Task<string> userinfoCallAsync(string access_token)
        {
            string output = "";
            // builds the  request
            string userinfoRequestURI = "https://www.googleapis.com/oauth2/v3/userinfo";

            // sends the request
            HttpWebRequest userinfoRequest = (HttpWebRequest)WebRequest.Create(userinfoRequestURI);
            userinfoRequest.Method = "GET";
            userinfoRequest.Headers.Add(string.Format("Authorization: Bearer {0}", access_token));
            userinfoRequest.ContentType = "application/x-www-form-urlencoded";
            userinfoRequest.Accept = "Accept=text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";

            // gets the response
            WebResponse userinfoResponse = await userinfoRequest.GetResponseAsync();
            using (StreamReader userinfoResponseReader = new StreamReader(userinfoResponse.GetResponseStream()))
            {
                // reads response body
                string userinfoResponseText = await userinfoResponseReader.ReadToEndAsync();
                //output(userinfoResponseText);
                output = userinfoResponseText;
            }

            return output;
        }
        #endregion

        #region update user
        [HttpPost("user/update")]
        [Authorize]
        // TODO: will update later
        public async Task<ActionResult> UpdateUserAsync()
        {
            var userClaims = HttpContext.User;

            var user = await _applicationUserManager.Current.GetUserAsync(userClaims);

            // TODO: will check again
            if (user == null)
                return StatusCode(500, "error!");
            if (user.EmailConfirmed == true)
                return StatusCode(400, "user's email is already confirmed!");

            //return await SendVerifyingEmailAsync(user, "updateUser", client);
            return Ok();
        }
        #endregion

        #region forget password
        [HttpPost("user/forgotPassword")]
        [AllowAnonymous]
        public async Task<ActionResult> ChangePasswordAfterEmailConfirm()
        {
            try
            {
                string requestBody = await GetRequestBodyAsQueryFormAsync(HttpContext.Request.Body);
                ChangePasswordParameters parameters = new ChangePasswordParameters(requestBody);

                // TODO: will think about client later
                var client = _clientDbServices.Find(parameters.ClientId.Value);

                var emailForChangingPassword = _emailServices.GetChangePasswordEmailByCode(parameters.Code.Value);
                var user = emailForChangingPassword.User;

                // TODO: will check again
                _applicationUserManager.Current.RemovePasswordAsync(user).Wait();
                _applicationUserManager.Current.AddPasswordAsync(user, parameters.NewPassword.Value).Wait();
                emailForChangingPassword.IsConfirmed = true;

                _emailServices.UpdateConfirmEmail(emailForChangingPassword);

                return Ok();
            }
            catch (Exception ex)
            {
                return StatusCode(500, ex.Message);
            }
        }

        [HttpGet("user/forgotPassword")]
        [AllowAnonymous]
        public async Task<ActionResult> ForgotPassword()
        {
            try
            {
                var queryString = HttpContext.Request.QueryString.Value;
                if (queryString == null)
                    return StatusCode(400, "query is missing!");
                var queryBody = queryString.Remove(0, 1).Split("&");

                string clientId = queryBody.GetFromQueryString(JwtClaimTypes.ClientId);
                if (string.IsNullOrEmpty(clientId))
                    return StatusCode(400, "client id is missing!");
                string email = queryBody.GetFromQueryString(JwtClaimTypes.Email);
                if (string.IsNullOrEmpty(email))
                    return StatusCode(400, "email is missing!");

                var client = _clientDbServices.Find(clientId);
                if (client == null)
                    return StatusCode(404, "client id may wrong!");

                // TODO: get user by email, by logic, username + email is unique for an user that is stored in db, but fow now, email may be duplicated for test
                var user = _applicationUserManager.Current.Users.FirstOrDefault(u => u.Email.Equals(email));
                await _emailServices.SendForgotPasswordCodeToEmailAsync(user, client);
            }
            catch (Exception ex)
            {
                return StatusCode(500, ex.Message);
            }
            return Ok();
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
    }
}
