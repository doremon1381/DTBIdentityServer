using static ServerUltilities.Identity.OidcConstants;

namespace ServerUltilities.Identity
{
    /// <summary>
    /// from https://github.com/IdentityServer/IdentityServer4/blob/main/src/IdentityServer4/src/Constants.cs
    /// </summary>
    public static class Constants
    {
        public const string IdentityServerName = "IdentityServer4";
        public const string IdentityServerAuthenticationType = IdentityServerName;
        public const string ExternalAuthenticationMethod = "external";
        public const string DefaultHashAlgorithm = "SHA256";

        public static readonly TimeSpan DefaultCookieTimeSpan = TimeSpan.FromHours(10);
        public static readonly TimeSpan DefaultCacheDuration = TimeSpan.FromMinutes(60);

        public static readonly List<string> SupportedResponseTypes = new List<string>
        {
            OidcConstants.ResponseTypes.Code,
            OidcConstants.ResponseTypes.Token,
            OidcConstants.ResponseTypes.IdToken,
            OidcConstants.ResponseTypes.IdTokenToken,
            OidcConstants.ResponseTypes.CodeIdToken,
            OidcConstants.ResponseTypes.CodeToken,
            OidcConstants.ResponseTypes.CodeIdTokenToken
        };

        public static readonly Dictionary<string, string> ResponseTypeToGrantTypeMapping = new Dictionary<string, string>
        {
            { OidcConstants.ResponseTypes.Code, GrantType.AuthorizationCode },
            { OidcConstants.ResponseTypes.Token, GrantType.Implicit },
            { OidcConstants.ResponseTypes.IdToken, GrantType.Implicit },
            { OidcConstants.ResponseTypes.IdTokenToken, GrantType.Implicit },
            { OidcConstants.ResponseTypes.CodeIdToken, GrantType.Hybrid },
            { OidcConstants.ResponseTypes.CodeToken, GrantType.Hybrid },
            { OidcConstants.ResponseTypes.CodeIdTokenToken, GrantType.Hybrid }
        };

        public static readonly List<string> AllowedGrantTypesForAuthorizeEndpoint = new List<string>
        {
            GrantType.AuthorizationCode,
            GrantType.Implicit,
            GrantType.Hybrid,
            // TODO: comment for now
            //GrantType.ClientCredentials,
            //GrantType.DeviceFlow

            // TODO: not support this grant type by default
            //GrantType.ResourceOwnerPassword,
            // TODO: not support this grant type by default
        };

        public static readonly List<string> SupportedCodeChallengeMethods = new List<string>
        {
            OidcConstants.CodeChallengeMethods.Plain,
            OidcConstants.CodeChallengeMethods.Sha256
        };
        
        public static readonly List<string> SupportedBasicAuthenticationEncodingMethods = new List<string>
        {
            OidcConstants.CodeChallengeMethods.Plain,
            OidcConstants.CodeChallengeMethods.Sha256
        };

        public enum ScopeRequirement
        {
            None,
            ResourceOnly,
            IdentityOnly,
            Identity
        }

        public static readonly Dictionary<string, ScopeRequirement> ResponseTypeToScopeRequirement = new Dictionary<string, ScopeRequirement>
        {
            { OidcConstants.ResponseTypes.Code, ScopeRequirement.None },
            { OidcConstants.ResponseTypes.Token, ScopeRequirement.ResourceOnly },
            { OidcConstants.ResponseTypes.IdToken, ScopeRequirement.IdentityOnly },
            { OidcConstants.ResponseTypes.IdTokenToken, ScopeRequirement.Identity },
            { OidcConstants.ResponseTypes.CodeIdToken, ScopeRequirement.Identity },
            { OidcConstants.ResponseTypes.CodeToken, ScopeRequirement.Identity },
            { OidcConstants.ResponseTypes.CodeIdTokenToken, ScopeRequirement.Identity }
        };

        public static readonly Dictionary<string, IEnumerable<string>> AllowedResponseModesForGrantType = new Dictionary<string, IEnumerable<string>>
        {
            { GrantType.AuthorizationCode, new[] { OidcConstants.ResponseModes.Query, OidcConstants.ResponseModes.FormPost, OidcConstants.ResponseModes.Fragment } },
            { GrantType.Hybrid, new[] { OidcConstants.ResponseModes.Fragment, OidcConstants.ResponseModes.FormPost }},
            { GrantType.Implicit, new[] { OidcConstants.ResponseModes.Fragment, OidcConstants.ResponseModes.FormPost }}
        };

        public static readonly List<string> SupportedResponseModes = new List<string>
        {
            OidcConstants.ResponseModes.FormPost,
            OidcConstants.ResponseModes.Query,
            OidcConstants.ResponseModes.Fragment
        };

        public static string[] SupportedSubjectTypes =
        {
            // TODO 
            //"pairwise",
            "public"
        };

        public static class SigningAlgorithms
        {
            public const string RSA_SHA_256 = "RS256";
        }

        public static readonly List<string> SupportedDisplayModes = new List<string>
        {
            OidcConstants.DisplayModes.Page,
            OidcConstants.DisplayModes.Popup,
            OidcConstants.DisplayModes.Touch,
            OidcConstants.DisplayModes.Wap
        };

        public static readonly List<string> SupportedPromptModes = new List<string>
        {
            OidcConstants.PromptModes.None,
            OidcConstants.PromptModes.Login,
            OidcConstants.PromptModes.Consent,
            OidcConstants.PromptModes.SelectAccount
        };
        public static readonly List<string> SupportConsentGrantedValue = new List<string>()
        {
            PromptConsentResult.Granted,
            PromptConsentResult.NotAllow
        };

        public static class KnownAcrValues
        {
            public const string HomeRealm = "idp:";
            public const string Tenant = "tenant:";

            public static readonly string[] All = { HomeRealm, Tenant };
        }

        public static Dictionary<string, int> ProtectedResourceErrorStatusCodes = new Dictionary<string, int>
        {
            { OidcConstants.ProtectedResourceErrors.InvalidToken,      401 },
            { OidcConstants.ProtectedResourceErrors.ExpiredToken,      401 },
            { OidcConstants.ProtectedResourceErrors.InvalidRequest,    400 },
            { OidcConstants.ProtectedResourceErrors.InsufficientScope, 403 }
        };

        public static int StatusCodeWithError(this string error)
        {
            return ProtectedResourceErrorStatusCodes[error];
        }

        public static readonly Dictionary<string, IEnumerable<string>> ScopeToClaimsMapping = new Dictionary<string, IEnumerable<string>>
        {
            { IdentityServerConstants.StandardScopes.Profile, new[]
                            {
                                JwtClaimTypes.Name,
                                JwtClaimTypes.FamilyName,
                                JwtClaimTypes.GivenName,
                                JwtClaimTypes.MiddleName,
                                JwtClaimTypes.NickName,
                                JwtClaimTypes.PreferredUserName,
                                JwtClaimTypes.Profile,
                                JwtClaimTypes.Picture,
                                JwtClaimTypes.WebSite,
                                JwtClaimTypes.Gender,
                                JwtClaimTypes.BirthDate,
                                JwtClaimTypes.ZoneInfo,
                                JwtClaimTypes.Locale,
                                JwtClaimTypes.UpdatedAt
                            }},
            { IdentityServerConstants.StandardScopes.Email, new[]
                            {
                                JwtClaimTypes.Email,
                                JwtClaimTypes.EmailVerified
                            }},
            { IdentityServerConstants.StandardScopes.Address, new[]
                            {
                                JwtClaimTypes.Address
                            }},
            { IdentityServerConstants.StandardScopes.Phone, new[]
                            {
                                JwtClaimTypes.PhoneNumber,
                                JwtClaimTypes.PhoneNumberVerified
                            }},
            { IdentityServerConstants.StandardScopes.OpenId, new[]
                            {
                                JwtClaimTypes.Subject
                            }},
            { CustomScope.Role, new[]
                {
                    JwtClaimTypes.Role
                }
            }
        };

        /// <summary>
        /// TODO: add for now
        /// </summary>
        public static class CustomScope
        {
            public static string Role = "role";
        }

        public static class UIConstants
        {
            // the limit after which old messages are purged
            public const int CookieMessageThreshold = 2;

            public static class DefaultRoutePathParams
            {
                public const string Error = "errorId";
                public const string Login = "returnUrl";
                public const string Consent = "consent";
                public const string Logout = "logoutId";
                public const string EndSessionCallback = "endSessionId";
                public const string UserCode = "userCode";
            }

            public static class DefaultRoutePaths
            {
                public const string Login = "/account/login";
                public const string Logout = "/account/logout";
                public const string Consent = "/consent";
                public const string Error = "/home/error";
                public const string DeviceVerification = "/device";
            }
        }

        public static readonly Dictionary<string, string> DiscoveryToEndpointMapping = new Dictionary<string, string>()
        {
            { EndpointNames.Authorize, Discovery.AuthorizationEndpoint },
            { EndpointNames.Token, Discovery.TokenEndpoint },
            { EndpointNames.Register, Discovery.RegistrationEndpoint },
            //{ EndpointNames.DeviceAuthorization, Discovery.DeviceAuthorizationEndpoint },
            { EndpointNames.Discovery, Discovery.DiscoveryEndpoint },
            //{ EndpointNames.Introspection, Discovery.IntrospectionEndpoint },
            //{ EndpointNames.Revocation, Discovery.RevocationEndpoint },
            //{ EndpointNames.EndSession, Discovery.EndSessionEndpoint },
            //{ EndpointNames.CheckSession, Discovery.CheckSessionEndpoint },
            { EndpointNames.UserInfo, Discovery.UserInfoEndpoint },
            { EndpointNames.Jwks, Discovery.JwksEndpoint },
            { EndpointNames.GoogleAuthorize, Discovery.GoogleAuthorizationEndpoint },
        };

        public static class EndpointNames
        {
            public const string Authorize = "Authorize";
            public const string Token = "Token";
            // TODO: Not in specs, but I currently use
            public const string Register = "Register";
            // TODO: Not in specs, but I currently use
            //public const string DeviceAuthorization = "DeviceAuthorization";
            public const string Discovery = "Discovery";
            //public const string Introspection = "Introspection";
            //public const string Revocation = "Revocation";
            //public const string EndSession = "Endsession";
            //public const string CheckSession = "Checksession";
            public const string UserInfo = "Userinfo";
            public const string Jwks = "JwksUri";

            public const string GoogleAuthorize = "GoogleAuthorize";
        }

        public static class ProtocolRoutePaths
        {
            //public const string ConnectPathPrefix = "connect";
            public const string OauthPathPrefix = "/oauth2";
            public const string AuthPathPrefix = "/auth";

            public const string Authorize = OauthPathPrefix + "/authorize";
            public const string AuthorizeCallback = Authorize + "/callback";
            public const string Discovery = ".well-known/openid-configuration";
            //public const string DiscoveryWebKeys = Discovery + "/jwks";
            public const string Jwks = OauthPathPrefix + "/jwks";
            public const string Token = OauthPathPrefix + "/token";
            public const string Revocation = OauthPathPrefix + "/revocation";
            public const string UserInfo = OauthPathPrefix + "/userinfo";
            public const string Introspection = OauthPathPrefix + "/introspect";
            public const string EndSession = OauthPathPrefix + "/endsession";
            public const string EndSessionCallback = EndSession + "/callback";
            public const string CheckSession = OauthPathPrefix + "/checksession";
            public const string DeviceAuthorization = OauthPathPrefix + "/deviceauthorization";
            public const string Register = AuthPathPrefix + "/register";
            public const string GoogleAuthorize = Authorize + "/google";
            //public const string ConfirmEmail = "confirmemail";

            public const string MtlsPathPrefix = OauthPathPrefix + "/mtls";
            public const string MtlsToken = MtlsPathPrefix + "/token";
            public const string MtlsRevocation = MtlsPathPrefix + "/revocation";
            public const string MtlsIntrospection = MtlsPathPrefix + "/introspect";
            public const string MtlsDeviceAuthorization = MtlsPathPrefix + "/deviceauthorization";

            public static readonly string[] CorsPaths =
            {
                Discovery,
                //DiscoveryWebKeys,
                Jwks,
                Token,
                UserInfo,
                Revocation
            };
        }

        public static class EnvironmentKeys
        {
            public const string IdentityServerBasePath = "idsvr:IdentityServerBasePath";
            [Obsolete("The IdentityServerOrigin constant is obsolete.")]
            public const string IdentityServerOrigin = "idsvr:IdentityServerOrigin"; // todo: deprecate
            public const string SignOutCalled = "idsvr:IdentityServerSignOutCalled";
        }

        public static class TokenTypeHints
        {
            public const string RefreshToken = "refresh_token";
            public const string AccessToken = "access_token";
        }

        public static List<string> SupportedTokenTypeHints = new List<string>
        {
            TokenTypeHints.RefreshToken,
            TokenTypeHints.AccessToken
        };

        public static class RevocationErrors
        {
            public const string UnsupportedTokenType = "unsupported_token_type";
        }

        public class Filters
        {
            // filter for claims from an incoming access token (e.g. used at the user profile endpoint)
            public static readonly string[] ProtocolClaimsFilter = {
                JwtClaimTypes.AccessTokenHash,
                JwtClaimTypes.Audience,
                JwtClaimTypes.AuthorizedParty,
                JwtClaimTypes.AuthorizationCodeHash,
                JwtClaimTypes.ClientId,
                JwtClaimTypes.Expiration,
                JwtClaimTypes.IssuedAt,
                JwtClaimTypes.Issuer,
                JwtClaimTypes.JwtId,
                JwtClaimTypes.Nonce,
                JwtClaimTypes.NotBefore,
                JwtClaimTypes.ReferenceTokenId,
                JwtClaimTypes.SessionId,
                JwtClaimTypes.Scope
            };

            // filter list for claims returned from profile service prior to creating tokens
            public static readonly string[] ClaimsServiceFilterClaimTypes = {
                // TODO: consider JwtClaimTypes.AuthenticationContextClassReference,
                JwtClaimTypes.AccessTokenHash,
                JwtClaimTypes.Audience,
                JwtClaimTypes.AuthenticationMethod,
                JwtClaimTypes.AuthenticationTime,
                JwtClaimTypes.AuthorizedParty,
                JwtClaimTypes.AuthorizationCodeHash,
                JwtClaimTypes.ClientId,
                JwtClaimTypes.Expiration,
                JwtClaimTypes.IdentityProvider,
                JwtClaimTypes.IssuedAt,
                JwtClaimTypes.Issuer,
                JwtClaimTypes.JwtId,
                JwtClaimTypes.Nonce,
                JwtClaimTypes.NotBefore,
                JwtClaimTypes.ReferenceTokenId,
                JwtClaimTypes.SessionId,
                JwtClaimTypes.Subject,
                JwtClaimTypes.Scope,
                JwtClaimTypes.Confirmation
            };

            public static readonly string[] JwtRequestClaimTypesFilter = {
                JwtClaimTypes.Audience,
                JwtClaimTypes.Expiration,
                JwtClaimTypes.IssuedAt,
                JwtClaimTypes.Issuer,
                JwtClaimTypes.NotBefore,
                JwtClaimTypes.JwtId
            };
        }

        public static class WsFedSignOut
        {
            public const string LogoutUriParameterName = "wa";
            public const string LogoutUriParameterValue = "wsignoutcleanup1.0";
        }

        public static class AuthorizationParamsStore
        {
            public const string MessageStoreIdParameterName = "authzId";
        }

        public static class CurveOids
        {
            public const string P256 = "1.2.840.10045.3.1.7";
            public const string P384 = "1.3.132.0.34";
            public const string P521 = "1.3.132.0.35";
        }
        public static class RegisterRequest
        {
            // TODO: by now, register user need client_id, I think only accept a register request from client, but will create another website for user register
            public const string ClientId = "client_id";
            //public const string RedirectUri = "redirect_uri";
            public const string State = "state";
            // TODO: allow nonce for now
            public const string Nonce = "nonce";

            public const string UserName = "UserName";
            public const string Password = "Password";
            public const string Register = "Register";

            public static string Email = "email";
            public static string FirstName = "first_name";
            public static string LastName = "last_name";
            public static string Roles = "roles";

            public static string Gender = "gender";
            public static string Phone = "phone";
        }

        public static class SignInGoogleRequest
        {
            public const string AuthorizationCode = "code";
            public const string RedirectUri = "redirect_uri";
            public const string CodeVerifier = "code_verifier";
            public const string ClientId = "client_id";
            //public const string Nonce = "nonce";
        }

        public static class ChangePasswordRequest
        {
            public const string Code = "code";
            public const string NewPassword = "password";
            public const string ClientId = "client_id";
        }

        public static class ForgotPasswordRequest
        {
            public const string ClientId = "client_id";
            public const string Email = "email";
        }

        public static class ClientCredentialsRequest
        {
            public const string GrantType = "grant_type";
            public const string Scope = "scope";
            public const string ClientId = "client_id";
            public const string ClientSecret = "client_secret";
        }

        internal static Dictionary<string, string> RouteMappingWithOpenIDAction = new Dictionary<string, string>()
        {
            { "Authorization", "Authorization" }
        };

        public static class TokenResponseRequiredHeaders
        {
            public const string CacheControl = "Cache-Control";
        }

        public static class RequiredHeaderValues
        {
            public const string CacheControl_NoStore = "no-store";
        }

        public static Dictionary<string, string> TokenResponseHeaderWithValue = new Dictionary<string, string>()
        {
            { TokenResponseRequiredHeaders.CacheControl, RequiredHeaderValues.CacheControl_NoStore }
        };
    }
}
