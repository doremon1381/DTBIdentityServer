using Google.Apis.Auth.OAuth2.Responses;
using IssuerOfClaims.Services.Database;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using ServerDbModels;
using ServerUltilities.Extensions;
using ServerUltilities.Identity;
using System.Security.Claims;
using System.Text.Encodings.Web;
using static ServerUltilities.Identity.OidcConstants;

namespace IssuerOfClaims.Services
{
    /// <summary>
    /// TODO: https://learn.microsoft.com/en-us/aspnet/core/fundamentals/middleware/write?view=aspnetcore-8.0&viewFallbackFrom=aspnetcore-2.2#per-request-dependencies
    /// </summary>
    public class AuthenticationServices : AuthenticationHandler<JwtBearerOptions>
    {
        private ITokenResponsePerHandlerDbServices _tokenResponsePerHandlerDbServices;
        private IApplicationUserManager _userManager;

        public AuthenticationServices(IOptionsMonitor<JwtBearerOptions> options, ILoggerFactory logger, UrlEncoder encoder,
            ITokenResponsePerHandlerDbServices tokenResponsePerHandlerDbServices, IApplicationUserManager userManager)
            : base(options, logger, encoder)
        {
            _tokenResponsePerHandlerDbServices = tokenResponsePerHandlerDbServices;
            _userManager = userManager;
        }

        protected async override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            try
            {
                var endpoint = this.Context.GetEndpoint();
                if (endpoint?.Metadata?.GetMetadata<IAllowAnonymous>() is object)
                    return AuthenticateResult.NoResult();

                // user login
                var authenticateInfor = this.Request.Headers.Authorization.ToString();
                ValidateAuthenticateInfo(authenticateInfor);

                UserIdentity user = GetUserUsingAuthenticationScheme(authenticateInfor);
                ClaimsPrincipal claimsPrincipal = CreateClaimPrincipal(user);

                ValidateClaimsPrincipal(claimsPrincipal);
                var ticket = IssueAuthenticationTicket(claimsPrincipal);

                return AuthenticateResult.Success(ticket);
            }
            catch (Exception ex)
            {
                return AuthenticateResult.Fail(ex.Message);
            }
        }

        private UserIdentity GetUserUsingAuthenticationScheme(string authenticateInfor)
        {
            // authentication with "Basic access" - username + password
            if (authenticateInfor.StartsWith(IdentityServerConfiguration.AUTHENTICATION_SCHEME_BASIC))
                return BasicAccess_FindUser(authenticateInfor);
            // authentication with Bearer" token - access token or id token, for now, I'm trying to implement
            //     , https://datatracker.ietf.org/doc/html/rfc9068#JWTATLRequest
            else if (authenticateInfor.StartsWith(IdentityServerConfiguration.AUTHENTICATION_SCHEME_BEARER))
                return BearerToken_FindUser(authenticateInfor);
            else
                throw new InvalidOperationException("Not implemented or does not have user with these informations!");
        }

        private UserIdentity BearerToken_FindUser(string authenticateInfor)
        {
            var accessToken = authenticateInfor.Replace(AuthenticationSchemes.AuthorizationHeaderBearer, "").Trim();
            var tokenResponse = _tokenResponsePerHandlerDbServices.FindByAccessToken(accessToken);

            return tokenResponse.TokenRequestHandler.User;
        }

        private UserIdentity BasicAccess_FindUser(string authenticateInfor)
        {
            var userNamePassword = authenticateInfor.Replace(IdentityServerConfiguration.AUTHENTICATION_SCHEME_BASIC, "").Trim().ToBase64Decode();
            ValidateIdentityCredentials(userNamePassword);

            return FindUser(userNamePassword);
        }

        private static void ValidateClaimsPrincipal(ClaimsPrincipal claimsPrincipal)
        {
            if (claimsPrincipal == null)
                throw new Exception("something is wrong...");
        }

        private static void ValidateAuthenticateInfo(string authenticateInfor)
        {
            if (string.IsNullOrEmpty(authenticateInfor))
                throw new Exception("Authentication's identity inside request headers is missing!");
        }

        private static void ValidateIdentityCredentials(string userNamePassword)
        {
            if (string.IsNullOrEmpty(userNamePassword))
                throw new InvalidOperationException("username and password is empty!");
        }

        private void ValidateUser(UserIdentity user, string password)
        {
            if (user == null)
                throw new InvalidOperationException("user is null!");

            if (string.IsNullOrEmpty(user.PasswordHash))
                throw new InvalidOperationException("try another login method, because this user's password is not set!");

            var valid = _userManager.Current.PasswordHasher.VerifyHashedPassword(user, user.PasswordHash, password);

            if (valid == PasswordVerificationResult.Failed)
                throw new Exception("wrong password!");
        }

        private AuthenticationTicket IssueAuthenticationTicket(ClaimsPrincipal claimPrincipal)
        {
            #region authenticate reason
            AddAuthenticateIdentityToContext(claimPrincipal);
            #endregion

            return new AuthenticationTicket(claimPrincipal, this.Scheme.Name);
        }

        private void AddAuthenticateIdentityToContext(ClaimsPrincipal principal)
        {
            Thread.CurrentPrincipal = principal;
            if (this.Context != null)
            {
                Context.User = principal;
            }
        }

        private UserIdentity FindUser(string userNamePassword)
        {
            string userName = userNamePassword.Split(":")[0];
            string password = userNamePassword.Split(":")[1];

            // TODO: Do authentication of userId and password against your credentials store here
            var user = _userManager.Current.Users
                .Include(user => user.IdentityUserRoles).ThenInclude(p => p.Role)
                .FirstOrDefault(u => u.UserName == userName);

            ValidateUser(user, password);

            return user;
        }

        private AuthenticationTicket IssuingTicketForParticularProcess(string schemaName, bool registeredProcess = false, bool offlineAccessProcess = false)
        {
            ClaimsPrincipal claims = new ClaimsPrincipal();

            if (registeredProcess == true && offlineAccessProcess == true)
                throw new InvalidOperationException("Wrong implement!");

            if (registeredProcess)
            {
                claims = GetClaimPrincipalForRegisterUser();
            }
            else if (offlineAccessProcess)
            {
                claims = GetClaimPrincipalForOfflineAccessUser();
            }

            return new AuthenticationTicket(claims, schemaName);
        }

        private string GetValidParameterFromQuery(string[] requestQuery, string parameterType)
        {
            string parameterValue = requestQuery.GetFromQueryString(parameterType);

            if (string.IsNullOrEmpty(parameterValue))
                throw new InvalidDataException("Parameter from query string must have value!");

            return parameterValue;
        }

        private ClaimsPrincipal GetClaimPrincipalForRegisterUser()
        {
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Anonymous, "RegisterUser")
            };
            var principal = new ClaimsPrincipal(new[] { new ClaimsIdentity(claims, IdentityServerConfiguration.AUTHENTICATION_SCHEME_ANONYMOUS) });
            return principal;
        }

        private ClaimsPrincipal GetClaimPrincipalForOfflineAccessUser()
        {
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Anonymous, "OfflineAccess")
            };
            var principal = new ClaimsPrincipal(new[] { new ClaimsIdentity(claims, IdentityServerConfiguration.AUTHENTICATION_SCHEME_ANONYMOUS) });
            return principal;
        }

        /// <summary>
        /// TODO: For now, use ClaimTypes of NetCore
        /// use when user login
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        private static ClaimsPrincipal CreateClaimPrincipal(UserIdentity user)
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
                new Claim(JwtClaimTypes.EmailVerified, user.IsEmailConfirmed.ToString()),
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
