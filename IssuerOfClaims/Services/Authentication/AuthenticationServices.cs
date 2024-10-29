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
using ServerDbModels;
using ServerUltilities.Extensions;
using ServerUltilities.Identity;
using System.Net;
using System.Security.Claims;
using System.Text.Encodings.Web;
using static ServerUltilities.Identity.OidcConstants;

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
                // TODO: if there is information for authentication inside header, go to authentication 
                if (IfAuthenticateInfoIsEmpty(Request.Headers.Authorization.ToString()))
                    if (IsGoingToAnonymousControllerOrEndpoint(endpointMetadata))
                        return AuthenticateResult.NoResult();

                // TODO: need to change from get user by auth code to verify authcode and get user from username or password
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
            // authentication with "Basic access" - username + password
            if (authenticateInfor.StartsWith(IdentityServerConfiguration.AUTHENTICATION_SCHEME_BASIC))
                return await BasicAccess_FindUserAsync(authenticateInfor);
            // authentication with Bearer" token - access token or id token, for now, I'm trying to implement
            //     , https://datatracker.ietf.org/doc/html/rfc9068#JWTATLRequest
            else if (authenticateInfor.StartsWith(IdentityServerConfiguration.AUTHENTICATION_SCHEME_BEARER))
                return await BearerToken_FindUserAsync(authenticateInfor);
            else
                throw new InvalidOperationException(ExceptionMessage.UNHANDLED_AUTHENTICATION_SCHEME);
        }

        private async Task<UserIdentity> BearerToken_FindUserAsync(string authenticateInfor)
        {
            var accessToken = authenticateInfor.Replace(IdentityServerConfiguration.AUTHENTICATION_SCHEME_BEARER, "").Trim();
            var tokenResponse = await _tokenResponsePerHandlerDbServices.FindByAccessTokenASync(accessToken);

            return tokenResponse.IdentityRequestHandler.User;
        }

        private async Task<UserIdentity> BasicAccess_FindUserAsync(string authenticateInfor)
        {
            var userNamePassword = authenticateInfor.Replace(IdentityServerConfiguration.AUTHENTICATION_SCHEME_BASIC, "").Trim().ToBase64Decode();

            return await FindUserAsync(userNamePassword);
        }

        private static bool IfAuthenticateInfoIsEmpty(string authenticateInfor)
        {
            if (string.IsNullOrEmpty(authenticateInfor))
                return true;

            return false;
        }

        private static void ValidateAuthenticationInfo(string authenticateInfor)
        {
            if (string.IsNullOrEmpty(authenticateInfor))
                throw new CustomException(ExceptionMessage.REQUEST_HEADER_MISSING_IDENTITY_INFO, HttpStatusCode.Unauthorized);
        }

        private void VefifyUser(UserIdentity user, string password)
        {
            if (user == null)
                throw new CustomException(ExceptionMessage.USER_NULL, HttpStatusCode.NotFound);

            if (string.IsNullOrEmpty(user.PasswordHash))
                throw new CustomException(ExceptionMessage.PASSWORD_NOT_SET, HttpStatusCode.NotFound);

            var valid = _userManager.Current.PasswordHasher.VerifyHashedPassword(user, user.PasswordHash, password);

            if (valid == PasswordVerificationResult.Failed)
                throw new CustomException(ExceptionMessage.WRONG_PASSWORD, HttpStatusCode.BadRequest);
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
                new Claim("Username", user.UserName),
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

            var principal = new ClaimsPrincipal(new[] { new ClaimsIdentity(claims, IdentityServerConfiguration.AUTHENTICATION_SCHEME_BASIC, user.UserName, ClaimTypes.Role) });

            return principal;
        }
    }
}
