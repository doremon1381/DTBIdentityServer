using IssuerOfClaims.Extensions;
using IssuerOfClaims.Models;
using IssuerOfClaims.Services.Database;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Controllers;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using ServerDbModels;
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
        private readonly ITokenForRequestHandlerDbServices _tokenResponsePerHandlerDbServices;
        private readonly IApplicationUserManager _userManager;

        public AuthenticationServices(IOptionsMonitor<JwtBearerOptions> options, ILoggerFactory logger, UrlEncoder encoder,
            ITokenForRequestHandlerDbServices tokenResponsePerHandlerDbServices, IApplicationUserManager userManager)
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
                //if (AuthorizeRequestWithAuthorizationHeader(authorizationHeader, Context.Request.Path.Value))
                //{
                //    Context.Response.StatusCode = (int)HttpStatusCode.BadRequest;
                //    return AuthenticateResult.Fail(ExceptionMessage.AUTHORIZATION_BASIC_NOT_SUPPORT_FOR_AUTHORIZE_ENDPOINT);
                //}

                // TODO: need to change from get user by auth code to verify authcode and get user from username or password
                //     : need to verify client identity before authentication, will be done later
                UserIdentity user = await GetUserUsingAuthenticationSchemeAsync(Request.Headers.Authorization.ToString());

                ClaimsPrincipal claimsPrincipal = await CreateClaimPrincipal(user);
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

        private static bool AuthorizeRequestWithAuthorizationHeader(string authorizationHeader, string path)
        {
            if (FindSchemeForAuthentication(authorizationHeader).Equals(AuthenticationSchemes.AuthorizationHeaderBasic)
                && path.Equals(ProtocolRoutePaths.Authorize))
                return true;
            return false;
        }

        private void Set401StatusCode()
        {
            Context.Response.StatusCode = (int)HttpStatusCode.Unauthorized;
        }

        private static bool IsGoingToAnonymousControllerOrEndpoint(EndpointMetadataCollection endpointMetadata)
        {
            if (IsAnonymouseController(endpointMetadata))
                return true;
            else if (IsAnonymousEndpoint(endpointMetadata))
                return true;

            return false;
        }

        private static bool IsAnonymousEndpoint(EndpointMetadataCollection endpointMetadata)
        {
            if (endpointMetadata?.GetMetadata<IAllowAnonymous>() is object)
                return true;
            return false;
        }

        private static bool IsAnonymouseController(EndpointMetadataCollection endpointMetadata)
        {
            var controllerAction = endpointMetadata.GetMetadata<ControllerActionDescriptor>();
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
        private async Task<UserIdentity> GetUserUsingAuthenticationSchemeAsync(string authenticateInfor)
        {
            ValidateAuthenticationInfo(authenticateInfor);

            return FindSchemeForAuthentication(authenticateInfor) switch
            {
                // authentication with "Basic access" - username + password
                AuthenticationSchemes.AuthorizationHeaderBasic => await BasicAccess_FindUserAsync(authenticateInfor),
                // authentication with Bearer" token - access token or id token, for now, I'm trying to implement
                //     , https://datatracker.ietf.org/doc/html/rfc9068#JWTATLRequest
                AuthenticationSchemes.AuthorizationHeaderBearer => await BearerToken_FindUserAsync(authenticateInfor),
                AuthenticationSchemes.AuthorizationHeaderPop => await PopHeader_FindUserAsync(authenticateInfor),
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
            else
            {
                throw new CustomException(ExceptionMessage.AUTHENTICATION_SCHEME_NOT_SUPPORT);
            }
        }


        private static bool IfAuthenticateInfoIsEmpty(string authenticateInfor)
        {
            if (string.IsNullOrEmpty(authenticateInfor))
                return true;

            return false;
        }

        private static void ValidateAuthenticationInfo(string authenticateInfor)
        {
            var scheme = authenticateInfor.Split(" ").First();
            if (string.IsNullOrEmpty(scheme))
                throw new CustomException(ExceptionMessage.REQUEST_HEADER_MISSING_IDENTITY_INFO);
            //if (scheme.ToUpper().Length)
        }

        private void VefifyUser(UserIdentity user, string password)
        {
            if (user == null)
                throw new CustomException(ExceptionMessage.USER_NULL);

            if (string.IsNullOrEmpty(user.PasswordHash))
                throw new CustomException(ExceptionMessage.PASSWORD_NOT_SET);

            var valid = _userManager.Current.PasswordHasher.VerifyHashedPassword(user, user.PasswordHash, password);

            if (valid == PasswordVerificationResult.Failed)
                throw new CustomException(ExceptionMessage.WRONG_PASSWORD);
        }

        private AuthenticationTicket IssueAuthenticationTicket(ClaimsPrincipal claimPrincipal)
        {
            #region authenticate reason
            AddAuthenticateIdentityToContext(claimPrincipal);
            #endregion

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
        private async Task<UserIdentity> BearerToken_FindUserAsync(string authenticateInfor)
        {
            var accessToken = authenticateInfor.Split(" ").Last().Trim();
            var tokenResponse = await _tokenResponsePerHandlerDbServices.FindByAccessTokenASync(accessToken);

            return tokenResponse.IdentityRequestHandler.User;
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
            var user = await _userManager.Current.Users
                //.Include(user => user.IdentityUserRoles).ThenInclude(p => p.Role)
                .FirstOrDefaultAsync(u => u.UserName == userName);

            VefifyUser(user, password);

            return user;
        }
        #endregion

        #region Pop
        private async Task<UserIdentity> PopHeader_FindUserAsync(string authenticateInfor)
        {
            var jwt = authenticateInfor.Split(" ").First().Trim();
            // TODO: get public key, verify, get user
            var userName = VerifyJwtTokenAndGetUserName(jwt);

            return await _userManager.Current.FindByNameAsync(userName);
        }

        private static string VerifyJwtTokenAndGetUserName(string jwt)
        {
            RSAParameters publicKey = RSAEncryptUtilities.ReadJsonKey();

            var tokenHandler = new JwtSecurityTokenHandler();

            // verify token
            var validateToken = new TokenValidationParameters()
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new RsaSecurityKey(publicKey),
                ValidateIssuer = false,
                ValidateAudience = false
            };

            ClaimsPrincipal userPrincipal = tokenHandler.ValidateToken(jwt, validateToken, out _);

            return userPrincipal.Claims.First(c => c.Type.Equals(JwtClaimTypes.Subject)).Value;
        }
        #endregion

        /// <summary>
        /// TODO: For now, use ClaimTypes of NetCore
        /// use when user login
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        private static async Task<ClaimsPrincipal> CreateClaimPrincipal(UserIdentity user)
        {
            var claims = new List<Claim>
            {
                new Claim(JwtClaimTypes.Subject, user.UserName),
                new Claim(ClaimTypes.Name, user.FullName),
                new Claim(ClaimTypes.AuthenticationMethod, AuthenticationMethods.Password),
                new Claim(ClaimTypes.Email, user.Email),
                new Claim(ClaimTypes.MobilePhone, user.PhoneNumber),
                new Claim(ClaimTypes.Gender, user.Gender),
                new Claim(JwtClaimTypes.Picture, user.Avatar),
                new Claim(JwtClaimTypes.UpdatedAt, user.UpdateTime.ToString()),
                new Claim(JwtClaimTypes.EmailVerified, user.EmailConfirmed.ToString()),
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString())
            };
            user.IdentityUserRoles.ForEach(p =>
            {
                claims.Add(new Claim(ClaimTypes.Role, p.Role.RoleCode));
            });

            var principal = new ClaimsPrincipal(new[] { new ClaimsIdentity(claims, OidcConstants.AuthenticationSchemes.AuthorizationHeaderBasic, user.UserName, ClaimTypes.Role) });

            return principal;
        }
    }
}
