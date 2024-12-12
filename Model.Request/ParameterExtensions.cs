using IssuerOfClaims.Models.Request.RequestParameter;
using ServerUltilities;
using ServerUltilities.Extensions;
using System.Net;
using System.Text.RegularExpressions;
using System.Web;
using static ServerUltilities.Identity.Constants;
using static ServerUltilities.Identity.OidcConstants;

namespace IssuerOfClaims.Models.Request
{
    internal static class ParameterExtensions
    {
        // TODO: https://www.rhyous.com/2010/06/15/csharp-email-regular-expression/
        //     : will learn regex later
        private static string _EmailRegex = "^[\\w!#$%&'*+\\-/=?\\^_`{|}~]+(\\.[\\w!#$%&'*+\\-/=?\\^_`{|}~]+)*@((([\\-\\w]+\\.)+[a-zA-Z]{2,4})|(([0-9]{1,3}\\.){3}[0-9]{1,3}))\\z";
        internal static Dictionary<string, Func<string, string, string>> SpecificMethodForInitiatingParameter = new Dictionary<string, Func<string, string, string>>()
        {
            { "scope", (str, str1) => { return Uri.UnescapeDataString(str); } },
            { AuthorizeRequest.RedirectUri, (str, str1) => { return Uri.UnescapeDataString(str); } },
            { AuthorizeRequest.ResponseMode, (responseMode, responseType) =>
            {
                return string.IsNullOrEmpty(responseMode) ? GetDefaultResponseModeByResponseType(responseType) : responseMode;
            }},
            { AuthorizeRequest.ResponseType, (str, str1) => { return Uri.EscapeDataString(str); } },
            { RegisterRequest.FirstName, (str, str1) => { return HttpUtility.UrlDecode(str); } },
            { RegisterRequest.LastName, (str, str1) => { return HttpUtility.UrlDecode(str); } },
            { RegisterRequest.Email, (str, str1) =>
                {
                    if (Regex.IsMatch(str, _EmailRegex))
                        return str;
                    else
                        throw new CustomException(ExceptionMessage.EMAIL_IS_WRONG, HttpStatusCode.BadRequest);
                }
            }
        };

        internal static Dictionary<string, ParameterPriority> AuthCodeParametersPriority = new Dictionary<string, ParameterPriority>()
        {
            { AuthorizeRequest.Scope, ParameterPriority.REQRUIRED },
            { AuthorizeRequest.ResponseType, ParameterPriority.REQRUIRED },
            { AuthorizeRequest.ClientId, ParameterPriority.REQRUIRED },
            { AuthorizeRequest.RedirectUri, ParameterPriority.REQRUIRED },
            { AuthorizeRequest.State, ParameterPriority.RECOMMENDED },
            { AuthorizeRequest.CodeChallenge, ParameterPriority.OPTIONAL },
            { AuthorizeRequest.CodeChallengeMethod, ParameterPriority.OPTIONAL },
            { AuthorizeRequest.Nonce, ParameterPriority.OPTIONAL },
            { AuthorizeRequest.ResponseMode, ParameterPriority.OPTIONAL },
            { AuthorizeRequest.Prompt, ParameterPriority.OPTIONAL },
            { AuthorizeRequest.MaxAge, ParameterPriority.OPTIONAL },
            { AuthorizeRequest.UiLocales, ParameterPriority.OPTIONAL },
            { AuthorizeRequest.IdTokenHint, ParameterPriority.OPTIONAL },

            { AuthorizeRequest.ConsentGranted, ParameterPriority.OPTIONAL }
        };

        //internal static Dictionary<string, ParameterPriority> HybridParametersPriority = new Dictionary<string, ParameterPriority>()
        //{
        //    { AuthorizeRequest.Scope, ParameterPriority.REQRUIRED },
        //    { AuthorizeRequest.ResponseType, ParameterPriority.REQRUIRED },
        //    { AuthorizeRequest.ClientId, ParameterPriority.REQRUIRED },
        //    { AuthorizeRequest.RedirectUri, ParameterPriority.REQRUIRED },
        //    { AuthorizeRequest.State, ParameterPriority.RECOMMENDED },
        //    { AuthorizeRequest.Nonce, ParameterPriority.REQRUIRED },
        //    { AuthorizeRequest.ResponseMode, ParameterPriority.OPTIONAL },
        //    { AuthorizeRequest.Prompt, ParameterPriority.OPTIONAL },
        //    { AuthorizeRequest.MaxAge, ParameterPriority.OPTIONAL },
        //    { AuthorizeRequest.UiLocales, ParameterPriority.OPTIONAL },
        //    { AuthorizeRequest.IdTokenHint, ParameterPriority.OPTIONAL },
        //    { AuthorizeRequest.ConsentGranted, ParameterPriority.OPTIONAL }
        //};

        // TODO: will check again
        internal static Dictionary<string, ParameterPriority> RegisterParamterPriority = new Dictionary<string, ParameterPriority>()
        {
            { RegisterRequest.State, ParameterPriority.OPTIONAL },
            { RegisterRequest.ClientId, ParameterPriority.OPTIONAL },
            { RegisterRequest.Nonce, ParameterPriority.OPTIONAL },
            { RegisterRequest.UserName, ParameterPriority.REQRUIRED },
            { RegisterRequest.Password, ParameterPriority.REQRUIRED },
            { RegisterRequest.FirstName, ParameterPriority.OPTIONAL },
            { RegisterRequest.LastName, ParameterPriority.OPTIONAL },
            // TODO: for now, email is optional, but I will change it to "REQRUIRED"
            //     , when adding condition to register useridentity to make one email is used only for one useridentity
            { RegisterRequest.Email, ParameterPriority.OPTIONAL },
            { RegisterRequest.Gender, ParameterPriority.OPTIONAL },
            { RegisterRequest.Phone, ParameterPriority.OPTIONAL},
            { RegisterRequest.Roles, ParameterPriority.OPTIONAL }
        };

        internal static Dictionary<string, ParameterPriority> SignInGoogleParamterPriority = new Dictionary<string, ParameterPriority>()
        {
            { SignInGoogleRequest.AuthorizationCode, ParameterPriority.REQRUIRED },
            { SignInGoogleRequest.RedirectUri, ParameterPriority.REQRUIRED },
            //{ SignInGoogleRequest.ClientSecret, ParameterPriority.REQRUIRED },
            { SignInGoogleRequest.ClientId, ParameterPriority.REQRUIRED },
            { SignInGoogleRequest.CodeVerifier, ParameterPriority.OPTIONAL }
        };

        internal static Dictionary<Type, OauthRequestType> ParametersForRequest = new Dictionary<Type, OauthRequestType>()
        {
            { typeof(AuthCodeParameters), OauthRequestType.AuthorizationCode },
            { typeof(RegisterParameters), OauthRequestType.Register },
            // TODO: will add later
            //{ typeof(TokenParameters), RequestType.Token },
            { typeof(SignInGoogleParameters), OauthRequestType.SignInGoogle },
            { typeof(AuthCodeTokenParameters), OauthRequestType.Token },
            { typeof(OfflineAccessTokenParameters), OauthRequestType.OfflineAccess },
            { typeof(ChangePasswordParameters), OauthRequestType.ChangePassword },
            { typeof(ClientCredentialsParameters), OauthRequestType.ClientCredentials },
        };

        internal static Dictionary<string, ParameterPriority> AuthCodeTokenParamterPriority = new Dictionary<string, ParameterPriority>()
        {
            { TokenRequest.Code, ParameterPriority.REQRUIRED },
            { TokenRequest.RedirectUri, ParameterPriority.REQRUIRED },
            { TokenRequest.ClientId, ParameterPriority.REQRUIRED },
            { TokenRequest.ClientSecret, ParameterPriority.REQRUIRED },
            { TokenRequest.Audience, ParameterPriority.OPTIONAL },
            { TokenRequest.Scope, ParameterPriority.OPTIONAL },
            { TokenRequest.CodeVerifier, ParameterPriority.OPTIONAL }
        };

        internal static Dictionary<string, ParameterPriority> OfflineAccessTokenParamterPriority = new Dictionary<string, ParameterPriority>()
        {
            { TokenRequest.RefreshToken, ParameterPriority.REQRUIRED },
            { TokenRequest.ClientId, ParameterPriority.REQRUIRED },
            { TokenRequest.ClientSecret, ParameterPriority.REQRUIRED },
            { TokenRequest.Scope, ParameterPriority.OPTIONAL },
        };

        internal static Dictionary<string, ParameterPriority> ChangePasswordParamterPriority = new Dictionary<string, ParameterPriority>()
        {
            { ChangePasswordRequest.Code, ParameterPriority.REQRUIRED },
            { ChangePasswordRequest.NewPassword, ParameterPriority.REQRUIRED },
            { ChangePasswordRequest.ClientId, ParameterPriority.REQRUIRED }
        };

        internal static Dictionary<string, ParameterPriority> ForgotPasswordParamterPriority = new Dictionary<string, ParameterPriority>()
        {
            { ForgotPasswordRequest.ClientId, ParameterPriority.REQRUIRED },
            { ForgotPasswordRequest.Email, ParameterPriority.REQRUIRED }
        };

        internal static Dictionary<string, ParameterPriority> ClientCredentialsParameterPriority = new Dictionary<string, ParameterPriority>()
        {
            { ClientCredentialsRequest.ClientId, ParameterPriority.REQRUIRED },
            { ClientCredentialsRequest.ClientSecret, ParameterPriority.REQRUIRED },
            { ClientCredentialsRequest.GrantType, ParameterPriority.REQRUIRED },
            { ClientCredentialsRequest.Scope, ParameterPriority.OPTIONAL },
        };

        private static string GetDefaultResponseModeByResponseType(string responseType)
        {
            string responseMode = "";

            // get grant type for response type
            string grantType = ResponseTypeToGrantTypeMapping[responseType];
            // map grant type with allowed response mode
            var responseModes = AllowedResponseModesForGrantType[grantType];

            // TODO: by default
            if (responseType.Equals(ResponseTypes.Code))
                responseMode = responseModes.First(m => m.Equals(ResponseModes.Query));
            else if (responseType.Equals(ResponseTypes.Token))
                responseMode = responseModes.First(m => m.Equals(ResponseModes.Fragment));

            return responseMode;
        }
    }
}
