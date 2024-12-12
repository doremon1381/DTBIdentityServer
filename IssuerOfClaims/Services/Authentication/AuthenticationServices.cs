using IssuerOfClaims.Extensions;
using IssuerOfClaims.Services.Database;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Controllers;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using IssuerOfClaims.Models.DbModel;
using ServerUltilities;
using ServerUltilities.Extensions;
using ServerUltilities.Identity;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Encodings.Web;
using static ServerUltilities.Identity.Constants;
using static ServerUltilities.Identity.OidcConstants;
using AuthenticationSchemes = ServerUltilities.Identity.OidcConstants.AuthenticationSchemes;

namespace IssuerOfClaims.Services.Authentication
{
    /// <summary>
    /// TODO: https://learn.microsoft.com/en-us/aspnet/core/fundamentals/middleware/write?view=aspnetcore-8.0&viewFallbackFrom=aspnetcore-2.2#per-request-dependencies
    /// </summary>
    public class AuthenticationServices : AuthenticationHandler<JwtBearerOptions>
    {
        private readonly ITokenForRequestHandlerDbService _tokenResponsePerHandlerDbServices;
        private readonly IApplicationUserManager _userManager;

        public AuthenticationServices(IOptionsMonitor<JwtBearerOptions> options, ILoggerFactory logger, UrlEncoder encoder,
            ITokenForRequestHandlerDbService tokenResponsePerHandlerDbServices, IApplicationUserManager userManager)
            : base(options, logger, encoder)
        {
            _tokenResponsePerHandlerDbServices = tokenResponsePerHandlerDbServices;
            _userManager = userManager;
        }

        protected async override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            try
            {
                var endpointMetadata = Context.GetEndpoint()?.Metadata;
                var authorizationHeader = Request.Headers.Authorization.ToString();
                // TODO: if there is information for authentication inside header, go to authentication 
                if (IfAuthenticateInfoIsEmpty(authorizationHeader))
                    if (IsGoingToAnonymousControllerOrEndpoint(endpointMetadata))
                        return AuthenticateResult.NoResult();

                // TODO: if "/oauth2/authorize" endpoint has Authentication header using basic scheme
                //     : , then server will response for that request an exception: "Authorization scheme is not support in this endpoint!".
                if (RequestToAuthorizeEndpointWithAuthorizationHeader(authorizationHeader, Context.Request.Path.Value))
                {
                    Context.Response.StatusCode = (int)HttpStatusCode.BadRequest;
                    return AuthenticateResult.Fail(ExceptionMessage.AUTHORIZATION_BASIC_NOT_SUPPORT_IN_AUTHORIZE_ENDPOINT);
                }

                // TODO: need to change from get user by auth code to verify authcode and get user from username or password
                //     : need to verify client identity before authentication, will be done later
                var identityInfo = await GetUserUsingAuthenticationSchemeAsync(Request.Headers.Authorization.ToString());

                ClaimsPrincipal claimsPrincipal = await Task.Run(() => CreateClaimPrincipal(identityInfo.UserIdentity, identityInfo.AuthenticationScheme));
                var ticket = IssueAuthenticationTicket(claimsPrincipal);

                return AuthenticateResult.Success(ticket);
            }
            catch (CustomException ex)
            {
                Set401StatusCode();
                return AuthenticateResult.Fail(ex.Message);
            }
            catch (Exception ex)
            {
                Set401StatusCode();
                return AuthenticateResult.Fail(ex);
            }
        }

        private static bool RequestToAuthorizeEndpointWithAuthorizationHeader(string authorizationHeader, string? path)
        {
            if (FindSchemeForAuthentication(authorizationHeader).Equals(AuthenticationSchemes.AuthorizationHeaderBasic)
                && !string.IsNullOrEmpty(path)
                && path.Equals(ProtocolRoutePaths.Authorize))
                return true;
            return false;
        }

        private void Set401StatusCode()
        {
            Context.Response.StatusCode = (int)HttpStatusCode.Unauthorized;
        }

        private static bool IsGoingToAnonymousControllerOrEndpoint(EndpointMetadataCollection? endpointMetadata)
        {
            if (IsAnonymouseController(endpointMetadata))
                return true;
            else if (IsAnonymousEndpoint(endpointMetadata))
                return true;

            return false;
        }

        private static bool IsAnonymousEndpoint(EndpointMetadataCollection? endpointMetadata)
        {
            if (endpointMetadata?.GetMetadata<IAllowAnonymous>() is object)
                return true;
            return false;
        }

        private static bool IsAnonymouseController(EndpointMetadataCollection? endpointMetadata)
        {
            var controllerAction = endpointMetadata?.GetMetadata<ControllerActionDescriptor>();
            if (controllerAction == null)
                return false;

            var typeInfo = controllerAction.ControllerTypeInfo;
            var controller = typeInfo.CustomAttributes.FirstOrDefault(c => c.AttributeType.Name.Equals(ControllerAttributeName.AllowAnonymous));
            if (controller is object)
            {
                return true;
            }
            return false;
        }

        /// <summary>
        /// WRONG_IMPLEMENT!: will replace this function 
        /// </summary>
        /// <param name="authenticateInfor"></param>
        /// <returns></returns>
        /// <exception cref="InvalidOperationException"></exception>
        private async Task<(UserIdentity UserIdentity, string AuthenticationScheme)> GetUserUsingAuthenticationSchemeAsync(string authenticateInfor)
        {
            ValidateAuthenticationInfo(authenticateInfor);

            return FindSchemeForAuthentication(authenticateInfor) switch
            {
                // authentication with "Basic access" - username + password
                AuthenticationSchemes.AuthorizationHeaderBasic => new(await BasicAccess_FindUserAsync(authenticateInfor), AuthenticationSchemes.AuthorizationHeaderBasic),
                // authentication with Bearer" token - access token or id token, for now, I'm trying to implement
                //     , https://datatracker.ietf.org/doc/html/rfc9068#JWTATLRequest
                AuthenticationSchemes.AuthorizationHeaderBearer => new(await BearerToken_FindUserAsync(authenticateInfor), AuthenticationSchemes.AuthorizationHeaderBearer),
                // TODO: for now, I allow id token can be use to authenticate, will update later
                AuthenticationSchemes.AuthorizationHeaderIdToken => new(await IdToken_FindUserAsync(authenticateInfor), AuthenticationSchemes.AuthorizationHeaderIdToken),
                // TODO
                //AuthenticationSchemes.ClientCredentialsBasic => new(await ClientCredentials_FindUserAsync(authenticateInfor), AuthenticationSchemes.ClientCredentialsBasic),
                // 
                //AuthenticationSchemes.AuthorizationHeaderRefreshToken => new (await RefreshToken_FindUserAsync(authenticateInfor), AuthenticationSchemes.AuthorizationHeaderRefreshToken),
                _ => throw new InvalidOperationException(ExceptionMessage.UNHANDLED_AUTHENTICATION_SCHEME)
            };
        }

        private static string FindSchemeForAuthentication(string authenticateInfor)
        {
            string scheme = authenticateInfor.Split(" ").FirstOrDefault().ToUpper();

            if (scheme.Equals(AuthenticationSchemes.AuthorizationHeaderBasic.ToUpper()))
            {
                return AuthenticationSchemes.AuthorizationHeaderBasic;
            }
            else if (scheme.Equals(AuthenticationSchemes.AuthorizationHeaderBearer.ToUpper()))
            {
                return AuthenticationSchemes.AuthorizationHeaderBearer;
            }
            else if (scheme.Equals(AuthenticationSchemes.AuthorizationHeaderIdToken.ToUpper()))
            {
                return AuthenticationSchemes.AuthorizationHeaderIdToken;
            }
            //else if (scheme.Equals(AuthenticationSchemes.ClientCredentialsBasic.ToUpper()))
            //{
            //    return AuthenticationSchemes.ClientCredentialsBasic;
            //}
            //else if (scheme.Equals(AuthenticationSchemes.AuthorizationHeaderRefreshToken.ToUpper()))
            //{
            //    return AuthenticationSchemes.AuthorizationHeaderRefreshToken;
            //}
            else
            {
                throw new CustomException(ExceptionMessage.AUTHENTICATION_SCHEME_NOT_SUPPORT);
            }
        }

        private static bool IfAuthenticateInfoIsEmpty(string authenticateInfo)
        {
            if (string.IsNullOrEmpty(authenticateInfo))
                return true;

            return false;
        }

        private static void ValidateAuthenticationInfo(string authenticateInfo)
        {
            var scheme = GetAuthenticationScheme(authenticateInfo);
            if (string.IsNullOrEmpty(scheme))
                throw new CustomException(ExceptionMessage.REQUEST_HEADER_MISSING_IDENTITY_INFO);
            //if (scheme.ToUpper().Length)
        }

        private void VefifyUserPassword(UserIdentity user, string password)
        {
            if (string.IsNullOrEmpty(user.PasswordHash))
                throw new CustomException(ExceptionMessage.PASSWORD_NOT_SET);

            var verificationResult = _userManager.Current.PasswordHasher.VerifyHashedPassword(user, user.PasswordHash, password);

            if (verificationResult == PasswordVerificationResult.Failed)
                throw new CustomException(ExceptionMessage.WRONG_USERNAME_OR_PASSWORD);
        }

        private AuthenticationTicket IssueAuthenticationTicket(ClaimsPrincipal claimPrincipal)
        {
            AddAuthenticateIdentityToContext(claimPrincipal);

            return new AuthenticationTicket(claimPrincipal, Scheme.Name);
        }

        private void AddAuthenticateIdentityToContext(ClaimsPrincipal principal)
        {
            Thread.CurrentPrincipal = principal;
            if (Context != null)
            {
                Context.User = principal;
            }
        }

        #region bearer token
        private async Task<UserIdentity> BearerToken_FindUserAsync(string authenticateInfo)
        {
            var accessToken = GetAuthenticationParameter(authenticateInfo);
            var tokenResponse = await _tokenResponsePerHandlerDbServices.FindByAccessTokenAsync(accessToken);

            // if user == null, then it is for client credential
            if (tokenResponse.IdentityRequestHandler.User != null)
            {
                return tokenResponse.IdentityRequestHandler.User;
            }
            else
            {
                //var user = await _userManager.Current.FindByIdAsync(tokenResponse.IdentityRequestHandler.Client.UserIdentityId.ToString());

                // TODO
                return null;
            }
        }
        #endregion

        #region basic access
        private async Task<UserIdentity> BasicAccess_FindUserAsync(string authenticateInfor)
        {
            var userNamePassword = authenticateInfor.Split(" ").Last().Trim().ToBase64Decode();

            return await FindUserAsync(userNamePassword);
        }
        private async Task<UserIdentity> FindUserAsync(string userNamePassword)
        {
            string userName = userNamePassword.Split(":")[0];
            string password = userNamePassword.Split(":")[1];

            // TODO: Do authentication of userId and password against your credentials store here
            var user = _userManager.Current.Users
                // TODO: for now
                //.Include(user => user.IdentityUserRoles).ThenInclude(p => p.Role)
                .FirstOrDefault(u => u.UserName == userName)
                ?? throw new CustomException(ExceptionMessage.USER_NULL);

            VefifyUserPassword(user, password);

            return user;
        }
        #endregion

        //#region refresh token
        //private async Task<UserIdentity> RefreshToken_FindUserAsync(string authenticateInfo)
        //{
        //    var refreshToken = GetAuthenticationParameter(authenticateInfo);
        //    var tokenResponse = await _tokenResponsePerHandlerDbServices.FindByRefreshTokenAsync(refreshToken);

        //    return tokenResponse.IdentityRequestHandler.User;
        //}
        //#endregion

        #region id token
        private async Task<UserIdentity> IdToken_FindUserAsync(string authenticateInfo)
        {
            string jwt = GetAuthenticationParameter(authenticateInfo);
            // TODO: get public key, verify, get user
            var userName = VerifyJwtTokenAndGetUserName(jwt);

            return await _userManager.Current.FindByNameAsync(userName)
                ?? throw new CustomException($"{nameof(IdToken_FindUserAsync)}: {ExceptionMessage.USER_NULL}");
        }

        /// <summary>
        /// authenticateInfo has form like : "{scheme} {value}"
        /// </summary>
        /// <param name="authenticateInfo"></param>
        /// <returns></returns>
        private static string GetAuthenticationParameter(string authenticateInfo)
        {
            return authenticateInfo.Split(" ").Last().Trim();
        }

        /// <summary>
        /// authenticateInfo has form like : "{scheme} {value}"
        /// </summary>
        /// <param name="authenticateInfo"></param>
        /// <returns></returns>
        private static string GetAuthenticationScheme(string authenticateInfo)
        {
            return authenticateInfo.Split(" ").First().Trim();
        }

        /// <summary>
        /// TODO: IDX10223: Lifetime validation failed. The token is expired. ValidTo (UTC): '12/7/2024 4:56:41 AM', Current time (UTC): '12/8/2024 7:07:29 AM'.
        /// </summary>
        /// <param name="jwt"></param>
        /// <returns></returns>
        /// <exception cref="CustomException"></exception>
        private static string VerifyJwtTokenAndGetUserName(string jwt)
        {
            // verify with current public key
            var resultOfVerification = VerifyToken(jwt, true);

            // try with the obsolete public key if the current key can not be used
            if (!resultOfVerification.IsValid)
                resultOfVerification = VerifyToken(jwt, false);
            // The token is not valid in either way.
            if (!resultOfVerification.IsValid)
                throw new CustomException("Token is invalid!", HttpStatusCode.BadRequest);

            // TODO: assumming if a token is valid, then it will has name identifier
            return resultOfVerification.ClaimPrincipal.Claims.First(c => c.Type.Equals(ClaimTypes.NameIdentifier)).Value;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="jwt"></param>
        /// <param name="tokenHandler"></param>
        /// <param name="verifyWithCurrentKey">to deal with a situation when the key is obsolete right after a jwt token was signed by that</param>
        /// <returns></returns>
        private static (ClaimsPrincipal ClaimPrincipal, bool IsValid) VerifyToken(string jwt, bool verifyWithCurrentKey)
        {
            var tokenHandler = new JwtSecurityTokenHandler();

            var securityKey = GetPublicKey(isObsolete: !verifyWithCurrentKey);
            var validateToken = CreateTokenValidationParameters(securityKey);
            var result = VerifyTokenWithPublicKey(tokenHandler, validateToken, jwt, securityKey);

            return result;
        }

        private static TokenValidationParameters CreateTokenValidationParameters(RsaSecurityKey securityKey)
        {
            return new TokenValidationParameters()
            {
                ValidateIssuerSigningKey = true,
                ValidateIssuer = false,
                ValidateAudience = false,
                ValidateLifetime = true,
                IssuerSigningKey = securityKey,
            };
        }

        private static (ClaimsPrincipal ClaimPrincipal, bool isValid) VerifyTokenWithPublicKey(JwtSecurityTokenHandler tokenHandler, TokenValidationParameters validateToken, string jwt, RsaSecurityKey securityKey)
        {
            ClaimsPrincipal user = tokenHandler.ValidateToken(jwt, validateToken, out SecurityToken securityToken);

            // TODO: still not sure about how to verify jwt key 
            bool isValid = user.Claims.Count() == 0 ? false : true;

            return (user, isValid);
        }

        private static RsaSecurityKey GetPublicKey(bool isObsolete = false)
        {
            RSAParameters publicKey = RSAEncryptUtilities.ReadJsonKey(isPublicKey: true, isObsolete);

            var securityKey = new RsaSecurityKey(publicKey);
            return securityKey;
        }
        #endregion

        #region client credentials
        //private static Task<UserIdentity> ClientCredentials_FindUserAsync(string authenticateInfor)
        //{
        //    var clientInfo = authenticateInfor.Split(" ").Last().Trim().ToBase64Decode();

        //}
        #endregion

        /// <summary>
        /// TODO: For now, use ClaimTypes of NetCore
        /// use when user login
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        private static ClaimsPrincipal CreateClaimPrincipal(UserIdentity user, string authenticationScheme)
        {
            var claims = new List<Claim>
            {
                new Claim(JwtClaimTypes.Subject, user.UserName),
                new Claim(ClaimTypes.Name, user.FullName),
                new Claim(ClaimTypes.AuthenticationMethod, AuthenticationMethods.Password),
                new Claim(ClaimTypes.Email, user.Email),
                new Claim(ClaimTypes.MobilePhone, user.PhoneNumber),
                new Claim(ClaimTypes.Gender, user.Gender),
                new Claim(JwtClaimTypes.Picture, user.Avatar ?? ""),
                new Claim(JwtClaimTypes.UpdatedAt, user.UpdateTime.ToString()),
                new Claim(JwtClaimTypes.EmailVerified, user.EmailConfirmed.ToString()),
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString())
            };
            // TODO: for now
            //user.IdentityUserRoles.ForEach(p =>
            //{
            //    claims.Add(new Claim(ClaimTypes.Role, p.Role.RoleCode));
            //});

            var principal = new ClaimsPrincipal(new[] { new ClaimsIdentity(claims, authenticationScheme, user.UserName, ClaimTypes.Role) });

            return principal;
        }
    }
}
