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
                {
                    return AuthenticateResult.NoResult();
                }

                // TODO: user login
                var headers = this.Request.Headers;
                var authenticateInfor = headers.Authorization.ToString();

                if (string.IsNullOrEmpty(authenticateInfor))
                    return AuthenticateResult.Fail("Authentication's identity inside request headers is missing!");

                // TODO: authentication allow "Basic" access - username + password
                if (authenticateInfor.StartsWith(IdentityServerConfiguration.AUTHENTICATION_SCHEME_BASIC))
                {
                    var userNamePassword = authenticateInfor.Replace(IdentityServerConfiguration.AUTHENTICATION_SCHEME_BASIC, "").Trim().ToBase64Decode();
                    if (string.IsNullOrEmpty(userNamePassword))
                        return AuthenticateResult.Fail("username and password is empty!");

                    string password = userNamePassword.Split(":")[1];

                    UserIdentity user = GetUser(userNamePassword);
                    if (string.IsNullOrEmpty(user.PasswordHash))
                        return AuthenticateResult.Fail("try another login method, because this user's password is not set!");

                    var valid = _userManager.Current.PasswordHasher.VerifyHashedPassword(user, user.PasswordHash, password);

                    if (valid == PasswordVerificationResult.Failed)
                        return AuthenticateResult.Fail("wrong password!");

                    #region authenticate reason
                    var principal = GetClaimPrincipal(user);

                    Thread.CurrentPrincipal = principal;
                    if (this.Context != null)
                    {
                        Context.User = principal;
                    }
                    #endregion

                    var ticket = new AuthenticationTicket(principal, this.Scheme.Name);

                    return AuthenticateResult.Success(ticket);

                }
                // TODO: and "Bearer" token - access token or id token, for now, I'm trying to implement
                //     : https://datatracker.ietf.org/doc/html/rfc9068#JWTATLRequest
                else if (headers.Authorization.ToString().StartsWith(AuthenticationSchemes.AuthorizationHeaderBearer))
                {
                    var accessToken = authenticateInfor.Replace(AuthenticationSchemes.AuthorizationHeaderBearer, "").Trim();

                    var tokenResponse = _tokenResponsePerHandlerDbServices.FindByAccessToken(accessToken);

                    #region authenticate reason
                    var principal = GetClaimPrincipal(tokenResponse.TokenRequestHandler.User);

                    Thread.CurrentPrincipal = principal;
                    if (this.Context != null)
                    {
                        Context.User = principal;
                    }
                    #endregion

                    var ticket = new AuthenticationTicket(principal, this.Scheme.Name);

                    return AuthenticateResult.Success(ticket);
                }

                // TODO: return none for now
                return AuthenticateResult.Fail("nonce");
            }
            catch (Exception ex)
            {
                return AuthenticateResult.Fail(ex.Message);
            }
        }

        private UserIdentity GetUser(string userNamePassword)
        {
            string userName = userNamePassword.Split(":")[0];

            // TODO: Do authentication of userId and password against your credentials store here
            var user = _userManager.Current.Users
                .Include(user => user.IdentityUserRoles).ThenInclude(p => p.Role)
                .FirstOrDefault(u => u.UserName == userName);
            if (user == null)
                throw new InvalidOperationException();

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
        private ClaimsPrincipal GetClaimPrincipal(UserIdentity user)
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

            //_UserClaims.Add(user, principal);
            return principal;
        }
    }
}
