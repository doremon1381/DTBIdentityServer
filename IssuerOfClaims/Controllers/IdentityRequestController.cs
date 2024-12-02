using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using IssuerOfClaims.Models.DbModel;
using ServerUltilities;
using ServerUltilities.Identity;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Authorization;
using IssuerOfClaims.Services.Database;
using IssuerOfClaims.Extensions;
using IssuerOfClaims.Services.Token;
using static ServerUltilities.Identity.OidcConstants;
using IssuerOfClaims.Services;
using Microsoft.IdentityModel.Tokens;
using IssuerOfClaims.Models;
using Google.Apis.Auth;
using System.Net.WebSockets;
using static ServerUltilities.Identity.Constants;
using IssuerOfClaims.Controllers.Attributes;
using IssuerOfClaims.Models.Request.Factory;
using IssuerOfClaims.Models.Request.RequestParameter;
using ServerUltilities.Extensions;

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
        private readonly IServiceProvider _serviceProvider;

        #region services
        private IApplicationUserManager _applicationUserManager;
        protected internal IApplicationUserManager ApplicationUserManager
        {
            get
            {
                return _serviceProvider.GetServiceLazily(ref _applicationUserManager);
            }
            set
            {
                _applicationUserManager = value;
            }
        }
        private IResponseManagerService _responseManager;

        protected internal IResponseManagerService ResponseManager
        {
            get
            {
                return _serviceProvider.GetServiceLazily(ref _responseManager);
            }
            private set
            {
                _responseManager = value;
            }
        }
        private IIdentityRequestHandlerService _requestHandlerServices;
        protected internal IIdentityRequestHandlerService RequestHandlerServices
        {
            get
            {
                return _serviceProvider.GetServiceLazily(ref _requestHandlerServices);
            }
            private set
            {
                _requestHandlerServices = value;
            }
        }

        private IClientDbService _clientDbServices;
        protected internal IClientDbService ClientDbServices
        {
            get
            {
                return _serviceProvider.GetServiceLazily(ref _clientDbServices);
            }
            private set
            {
                _clientDbServices = value;
            }
        }


        private GoogleClientConfiguration _googleClientConfiguration;
        protected internal GoogleClientConfiguration GoogleClientConfiguration
        {
            get
            {                
                return _serviceProvider.GetServiceLazily(ref _googleClientConfiguration);
            }
            private set
            {
                _googleClientConfiguration = value;
            }
        }
        #endregion

#pragma warning disable CS8618 // Non-nullable field must contain a non-null value when exiting constructor. Consider declaring as nullable.
        public IdentityRequestController(ILogger<IdentityRequestController> logger
#pragma warning restore CS8618 // Non-nullable field must contain a non-null value when exiting constructor. Consider declaring as nullable.
            , IServiceProvider serviceProvider
            , IIdentityRequestHandlerService requestHandlerServices)
        {
            _logger = logger;
            _serviceProvider = serviceProvider;

            _requestHandlerServices = requestHandlerServices;
        }

        #region catch authorize request
        /// <summary>
        /// authorization_endpoint: support the use of the HTTP GET.
        /// https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
        /// </summary>
        /// <returns></returns>
        [HttpGet("authorize")]
        [Authorize]
        public async Task<ActionResult> AuthenticationGetAsync()
        {
            // 1. Get authorization request from server
            // 2. Return an http 302 message to server, give it a nonce cookie (for now, ignore this part),
            //    if asking for google, then send a redirect to google to get authorization code
            //    if basic access (I mean implicit grant - form_post or not), then return a redirect to another request to identity server - send request to "authentication/basicAccess" route
            // 3. With many account can be found in one useragent (chrome or ...) - for example, using more than one google account when using google authentication without explicit authuser as request parameter
            //  , need to open a consent prompt to let resource owner chooses which one will be used for authorization request.
            //  With the way I want to use web application, I will not let more than one user interacts with server in one useragent.
            //  So basically, I can use "none" as prompt value by defualt, but will think about some changes in future.

            var parameters = new AuthCodeParametersFactory(HttpContext.Request.QueryString.Value)
                .ExtractParametersFromQuery();

            return await AuthenticationAsync(parameters);
        }

        /// <summary>
        /// authorization_endpoint: support the use of the HTTP POST.
        ///  https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
        /// </summary>
        /// <returns></returns>
        [HttpPost("authorize")]
        [Authorize]
        public async Task<ActionResult> AuthenticationPostAsync()
        {
            var query = await Utilities.SerializeFormAsync(HttpContext.Request.Body);

            var parameters = new AuthCodeParametersFactory(query)
                .ExtractParametersFromQuery();

            return await AuthenticationAsync(parameters);
        }

        // TODO: add callback to server after login success
        /// <summary>
        /// catch request from login web ui after consent is granted
        /// </summary>
        /// <returns></returns>
        [HttpGet("authorize/callback")]
        [Authorize]
        public async Task<ActionResult> AuthenticationCalbackAsync()
        {
            return new EmptyResult();
        }

        private async Task<ActionResult> AuthenticationAsync(AuthCodeParameters parameters)
        {
            var client = await ClientDbServices.FindAsync(parameters.ClientId.Value);

            await Task.Run(() => ValidateRedirectUris(parameters.RedirectUri.Value, client));
            if (ConsentResultIsNotAllowed(parameters.ConsentGranted.Value))
            {
                await RedirectIfAccessToResourcesIsNotAllowed(HttpContext, parameters.RedirectUri.Value, parameters.State.Value);
                return new EmptyResult();
            }

            // Authentication by using one of these flows
            switch (GetMappingGrantType(parameters.ResponseType.Value))
            {
                case GrantType.Implicit:
                    return await ToImplicitGrantProcessAsync(parameters);
                case GrantType.ClientCredentials:
                    throw new CustomException(ExceptionMessage.NOT_IMPLEMENTED, HttpStatusCode.NotImplemented);
                case GrantType.Hybrid:
                    return await ToHybridFlowProcessAsync(parameters);
                case GrantType.AuthorizationCode:
                    return await IssueAuthorizationCodeAsync(parameters);
                default:
                    throw new CustomException(ExceptionMessage.NOT_IMPLEMENTED, HttpStatusCode.NotImplemented);
            }
        }

        private static async Task RedirectIfAccessToResourcesIsNotAllowed(HttpContext context, string redirectUri, string state)
        {
            // TODO: send request as redirect response to redirect uri
            //     : with query string has error=access_denied
            var location = CreateDeniedResponseLocation(redirectUri, state);

            context.Response.Headers.Append("location", location);
            context.Response.StatusCode = 302;
            await context.Response.CompleteAsync(); // Ensure response is completed
        }

        private static string CreateDeniedResponseLocation(string redirectUri, string state)
        {
            var stateValue = string.IsNullOrEmpty(state) ? "" : $"&state={state}";

            return $"{redirectUri}?error=access_denied{stateValue}";
        }

        private static bool ConsentResultIsNotAllowed(string consentValue)
        {
            if (consentValue.Equals(PromptConsentResult.NotAllow))
            {
                return true;
            }
            return false;
        }

        private static string GetMappingGrantType(string responseType)
        {
            return Constants.ResponseTypeToGrantTypeMapping[responseType];
        }

        private static void ValidateRedirectUris(string redirectUri, Client client)
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

        #region hybrid flow
        private async Task<ActionResult> ToHybridFlowProcessAsync(AuthCodeParameters parameters)
        {
            // TODO: comment for now
            //     : by using AuthenticateHanlder, in this step, authenticated is done
            //     : get user, create authorization code, save it to login session and out

            // TODO: because I also use AuthCodeParameters to extract parameter from query string in authorization code flow
            //     : then at this step, need to ensure response type and nonce must have value according to Hybrid flow request validation of OpenID
            SpecialValidateAuthCodeParametersForHybridFlow(parameters);

            var user = await VerifyAndGetUserFromContextAsync();
            var client = await ClientDbServices.FindAsync(parameters.ClientId.Value);

            ACF_I_ValidateScopes(parameters.Scope.Value, client);

            string authorizationCode = IssueAuthorizationCode();

            // create return parameters 
            // TODO: need to create access token, id token before this step
            //     : adding id token or access token along with respone base on response types of parameters
            string response = await ResponseManager.HybridFlowResponseAsync(parameters, user, client, authorizationCode);

            await ACF_I_SendRedirectResponse(parameters, response);

            return new EmptyResult();
        }

        private static void SpecialValidateAuthCodeParametersForHybridFlow(AuthCodeParameters parameters)
        {
            if (!parameters.ResponseType.HasValue)
                throw new CustomException($"{nameof(ToHybridFlowProcessAsync)}: {ExceptionMessage.EMPTY_RESPONSE_TYPE}", HttpStatusCode.BadRequest);
            if (!parameters.Nonce.HasValue)
                throw new CustomException($"{nameof(ToHybridFlowProcessAsync)}: {ExceptionMessage.EMPTY_NONCE}", HttpStatusCode.BadRequest);
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

            var user = await VerifyAndGetUserFromContextAsync();
            var client = await ClientDbServices.FindAsync(@params.ClientId.Value);

            ACF_I_ValidateScopes(@params.Scope.Value, client);

            string authorizationCode = IssueAuthorizationCode();

            // create return parameters 
            string response = await ResponseManager.ACF_I_CreateResponseAsync(@params, user, client, authorizationCode);

            await ACF_I_SendRedirectResponse(@params, response);

            return new EmptyResult();
        }

        private async Task ACF_I_SendRedirectResponse(AuthCodeParameters @params, string response)
        {
            HttpContext.Response.Headers.Append("location", string.Format("{0}{1}", @params.RedirectUri.Value, response));
            HttpContext.Response.StatusCode = 302;
            await HttpContext.Response.WriteAsync(response);
            await HttpContext.Response.CompleteAsync(); // Ensure response is completed
        }

        /// <summary>
        /// Use for now, but may change in the future
        /// </summary>
        /// <returns></returns>
        private string IssueAuthorizationCode()
        {
            return RNGCryptoServicesUltilities.RandomStringGeneratingWithLength(32);
        }

        private async Task<UserIdentity> VerifyAndGetUserFromContextAsync()
        {
            var user = await ApplicationUserManager.Current.GetUserAsync(HttpContext.User);

            return user ?? throw new CustomException(ExceptionMessage.USER_NULL);
        }

        private static bool ACF_I_ValidateScopes(string scopes, Client client)
        {
            var variables = scopes.Split(" ");
            foreach (var s in variables)
            {
                if (!client.AllowedScopes.Contains(s))
                    throw new CustomException(ExceptionMessage.SCOPES_NOT_ALLOWED, HttpStatusCode.BadRequest);
            }
            return true;
        }

        #region obsolate
        private static async Task ACF_I_SendResponseAsync(AuthCodeParameters @params, string authorizationCode, string responseMessage)
        {
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
            httpClient.Timeout = TimeSpan.FromSeconds(10);
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
                throw new CustomException(ex.Message);
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
        #endregion
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
        private async Task<ActionResult> ToImplicitGrantProcessAsync(AuthCodeParameters parameters)
        {
            // TODO: for this situation, Thread and http context may not need
            var principal = HttpContext.User;

            // TODO: at this step, user cannot be null
            UserIdentity? user = await VerifyAndGetUserFromContextAsync();

            var client = await ClientDbServices.FindAsync(parameters.ClientId.Value);

            IGF_ValidateNonce(parameters.Nonce.Value);

            var response = await ResponseManager.IGF_GetResponseAsync(user, parameters, client);

            await IGF_SendRedirectResponse(parameters, response);

            // TODO: will learn how to use it later
            return new EmptyResult();
        }

        private async Task IGF_SendRedirectResponse(AuthCodeParameters parameters, string response)
        {
            // TODO: temporary
            HttpContext.Response.Headers.Location = parameters.RedirectUri.Value;
            HttpContext.Response.StatusCode = (int)HttpStatusCode.Redirect;
            // TODO: will learn how to use this function
            await WriteHtmlAsync(HttpContext.Response, response);
            // ensure everything is sent to client
            await HttpContext.Response.CompleteAsync();
        }

        /// <summary>
        /// TODO: more information https://openid.net/specs/openid-connect-core-1_0.html#ImplicitFlowSteps
        /// <para>In this flow, nonce must have value from request</para>
        /// </summary>
        /// <param name="nonce"></param>
        private bool IGF_ValidateNonce(string nonce)
        {
            if (string.IsNullOrEmpty(nonce))
                throw new CustomException(ExceptionMessage.NONCE_MUST_HAVE_VALUE_WITH_IMPLICIT_GRANT_FLOW, HttpStatusCode.BadRequest);
            return true;
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
        #endregion

        #region Issue token
        // TODO: try to implement from
        //     : https://www.oauth.com/oauth2-servers/making-authenticated-requests/refreshing-an-access-token/
        //     : Token Request Validation: https://openid.net/specs/openid-connect-core-1_0.html
        //     : only allow authorization code to get access token and id token,
        //     : access token will be use for scope uri, like userinfo or email...
        [HttpPost("token")]
        [AllowAnonymous]
        public async Task<ActionResult> TokenEndpointPostAsync()
        {
            string requestBody = await Utilities.SerializeFormAsync(HttpContext.Request.Body);
            string grantType = ToR_GetGrantType(requestBody);

            switch (grantType)
            {
                case OidcConstants.GrantTypes.RefreshToken:
                    {
                        // 1. check token response information.
                        // 2. check request for that response, which it has offline access or not
                        // 3. check expired time of refresh token and access token
                        // 4. issue new access token if there is no problem

                        return await IssueTokenForRefreshTokenAsync(requestBody);
                    }
                case OidcConstants.GrantTypes.AuthorizationCode:
                    return await IssueTokenForAuthorizationCodeAsync(requestBody);
                default:
                    return StatusCode((int)HttpStatusCode.NotImplemented, ExceptionMessage.NOT_IMPLEMENTED);
            }
        }

        /// <summary>
        /// TODO: for test
        /// </summary>
        /// <param name="requestBody"></param>
        /// <returns></returns>
        /// <exception cref="CustomException"></exception>
        private static string ToR_GetGrantType(string requestBody)
        {
            string? grantType = null;
            var span = requestBody.Remove(0, 1).Split("&").AsSpan();

            var enumerator = span.GetEnumerator();
            while(enumerator.MoveNext())
            {
                if (enumerator.Current.StartsWith(TokenRequest.GrantType))
                    grantType = enumerator.Current.Replace($"{TokenRequest.GrantType}=", "");
                else
                    continue;
            }

            return grantType ?? throw new CustomException(string.Format("{0}: grant type does not have value!", nameof(ToR_GetGrantType)));
        }

        private async Task<ActionResult> IssueTokenForRefreshTokenAsync(string requestBody)
        {
            // 1. check refresh token type, external or local
            // 2. if local, check expired time, issue token
            // 3. if external, send request to external source to get response
            var parameters = new OfflineAccessTokenParametersFactory(requestBody)
                .ExtractParametersFromQuery();

            var tokenResponses = await ResponseManager.IssueTokenByRefreshToken(parameters.RefreshToken.Value);

            return StatusCode((int)HttpStatusCode.OK, tokenResponses);
        }

        private async Task<ActionResult> IssueTokenForAuthorizationCodeAsync(string requestBody)
        {
            // TODO: get from queryString, authorization code
            //     : get user along with authorization code inside latest login session (of that user)
            //     : create access token and id token, send it to client
            var parameters = new AuthCodeTokenRequestParametersFactory(requestBody)
                .ExtractParametersFromQuery();

            // TODO: for now, every request, by default in scop will have openid, so ignore this part of checking now
            //     : Verify that the Authorization Code used was issued in response to an OpenID Connect Authentication Request(so that an ID Token will be returned from the Token Endpoint).
            var requestHandler = await RequestHandlerServices.FindByAuthCodeAsync(parameters.Code.Value);

            // TODO: will change to use email when allow using identity from another source
            UserIdentity user = await ACF_II_VerifyAndGetUserIdentityAsync(requestHandler.User.UserName);
            var client = await ACF_II_VerifyAndGetClientAsync(parameters.ClientId.Value, parameters.ClientSecret.Value, requestHandler);

            ACF_II_VerifyRedirectUris(parameters.RedirectUri.Value, requestHandler.RequestSession.RedirectUri);
            ACF_II_VerifyCodeChallenger(parameters.CodeVerifier.Value, requestHandler);

            // TODO: issue token from TokenManager
            var response = await ResponseManager.ACF_II_CreateResponseAsync(client.Id, client.ClientId, requestHandler.Id);

            // TODO: https://openid.net/specs/openid-connect-core-1_0.html#TokenResponse
            //     : will think about it later, for now, I follow the openid specs
            HttpContext.Response.Headers.CacheControl = RequiredHeaderValues.CacheControl_NoStore;

            return StatusCode((int)HttpStatusCode.OK, response);
        }

        // TODO: will test again
        private async Task<UserIdentity> ACF_II_VerifyAndGetUserIdentityAsync(string userName)
        {
            return await ApplicationUserManager.GetUserAsync(userName);
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
        private async Task<Client> ACF_II_VerifyAndGetClientAsync(string clientId, string clientSecret, IdentityRequestHandler tokenRequestHandler)
        {
            Client client = await ClientDbServices.FindAsync(clientId, clientSecret);

            // TODO: status code may wrong
            return tokenRequestHandler.ClientId.Equals(client.Id) 
                ? client 
                : throw new CustomException(ExceptionMessage.CLIENT_OF_TOKEN_REQUEST_IS_DIFFERENT_WITH_AUTH_CODE_REQUEST);
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
            var user = await ApplicationUserManager.Current.GetUserAsync(HttpContext.User);

            if (user == null)
                throw new InvalidOperationException(ExceptionMessage.OBJECT_NOT_FOUND);

            object responseBody = await Task.Run(() => ResponseForUserInfoRequest(user));
            // TODO: has some bug inside this function, will fix it later
            //string responseBody = await Utilities.CreateUserInfoResponseAsync(user);

            return StatusCode((int)HttpStatusCode.OK, responseBody);
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

        #region Google authentication
        //[HttpPost("v{version:apiVersion}/authorize/google")]
        [HttpPost("authorize/google")]
        [AllowAnonymous]
        // TODO: comment for now, but when everything is done, this policy must be used, 
        //     : only identityserver's clients can use this endpoint, not user-agent
        public async Task<ActionResult> GoogleAuthenticating()
        {
            var parameters = await Google_GetQueryParameters(HttpContext.Request.Body);

            // verify client's information from query, pass if a client is found
            var client = await ClientDbServices.FindAsync(parameters.ClientId.Value, parameters.ClientSecret.Value);
            // get token from google
            var googleResponse = await Google_SendTokenRequestAsync(parameters, GoogleClientConfiguration);

            // verify Google id token
            GoogleJsonWebSignature.Payload payload = await GoogleJsonWebSignature.ValidateAsync(googleResponse.IdToken);

            // ensure google's access token can be used
            await userinfoCallAsync(googleResponse.AccessToken, GoogleClientConfiguration.UserInfoUri);

            // create new user or map google user info to current user
            var user = await ApplicationUserManager.GetOrCreateUserByEmailAsync(payload);

            // create client's response
            var response = await ResponseManager.AuthGoogle_CreateResponseAsync(parameters, client, googleResponse, payload, user);

            // TODO: will need to create new user if current user with this email is not have
            //     : after that, create login session object and save to db
            //     : after create login session, authentication then will perform
            return Ok(response);
        }

        private static async Task<SignInGoogleParameters> Google_GetQueryParameters(Stream body)
        {
            string requestQuery = await Utilities.SerializeFormAsync(body);

            // TODO: add '?' before requestBody to get query form of string
            // , AbtractRequestParamters instances use request query as parameter
            var parameters = new SignInGoogleParametersFactory(requestQuery)
                .ExtractParametersFromQuery();
            return parameters;
        }

        private static async Task<GoogleResponse> Google_SendTokenRequestAsync(SignInGoogleParameters parameters, GoogleClientConfiguration config)
        {
            string tokenRequestBody = await Task.Run(() => Google_CreateTokenRequestBody(parameters, config));

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
                result.TryGetValue("expires_in", out string expiresIn);

                expired_in = double.Parse($"{expiresIn}");
                accessTokenIssueAt = DateTime.Now;
                // TODO: validate at_hash from id_token is OPTIONAL in some flows (hybrid flow,...),
                //     : I will check when to implement it later, now, better it has than it doesn't
                //     : comment for now
                //ValidateAtHash(id_token, access_token);
            }

            return new GoogleResponse(access_token, id_token, refresh_token, accessTokenIssueAt, expired_in);
        }

        private static string Google_CreateTokenRequestBody(SignInGoogleParameters parameters, GoogleClientConfiguration config)
        {
            // builds the request
            return string.Format("code={0}&redirect_uri={1}&client_id={2}&code_verifier={3}&client_secret={4}&scope=&grant_type=authorization_code",
                parameters.AuthorizationCode.Value,
                parameters.RedirectUri.Value,
                config.ClientId,
                parameters.CodeVerifier.Value,
                config.ClientSecret);
        }


        /// <summary>
        /// TODO: validate at_hash from id_token is OPTIONAL in some flow,
        ///     : I will check when to implement it later, now, better it has than it doesn't
        ///     https://openid.net/specs/openid-connect-core-1_0.html#FormSerialization
        ///     and https://stackoverflow.com/questions/30356460/how-do-i-validate-an-access-token-using-the-at-hash-claim-of-an-id-token
        /// </summary>
        /// <param name="id_token"></param>
        /// <param name="access_token"></param>
        private static bool ValidateAtHash(string id_token, string access_token)
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

        private static JwtSecurityToken DecodeIdTokenString(string id_token)
        {
            var handler = new JwtSecurityTokenHandler();
            var jwtSecurityToken = handler.ReadJwtToken(id_token);
            return jwtSecurityToken;
        }

        private static async Task<string> userinfoCallAsync(string access_token, string userInfoUri)
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
            // TODO: using temporary
            var publicKey = RSAEncryptUtilities.ReadJsonKey();

            return StatusCode((int)HttpStatusCode.OK, JsonConvert.SerializeObject(publicKey, Formatting.Indented));
        }
        #endregion
    }
}
