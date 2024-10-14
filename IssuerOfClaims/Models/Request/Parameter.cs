using IssuerOfClaims.Extensions;
using IssuerOfClaims.Models;
using ServerUltilities.Identity;
using System.Net;
using System.Web;
using static ServerUltilities.Identity.Constants;
using static ServerUltilities.Identity.OidcConstants;

namespace IssuerOfClaims.Models.Request
{
    /// <summary>
    /// Store value of request parameter
    /// </summary>
    public class Parameter
    {
        public string Name { get; private set; } = string.Empty;
        public string Value { get; private set; } = string.Empty;

        public ParameterPriority Priority { get; private set; } = ParameterPriority.OPTIONAL;

        public bool HasValue => !string.IsNullOrEmpty(Value);

        public Parameter(string name, RequestPurpose requestPurpose)
        {
            Name = name;
            SetParameterPriority(requestPurpose);
        }

        public void SetValue(string value)
        {
            VerifyRequiredParameter(value);
            Value = value;
        }

        private bool VerifyRequiredParameter(string value)
        {
            if (Priority == ParameterPriority.REQRUIRED)
            {
                if (string.IsNullOrEmpty(value))
                    throw new CustomException((int)HttpStatusCode.BadRequest, $"{Name} : {ExceptionMessage.REQUIRED_PARAMETER_NOT_NULL}");
            }

            return true;
        }

        private void SetParameterPriority(RequestPurpose requestType)
        {
            Priority = requestType switch
            {
                RequestPurpose.AuthorizationCode => ParameterUtilities.AuthCodeParameterPriority[Name],
                RequestPurpose.Register => ParameterUtilities.RegisterParamterPriority[Name],
                RequestPurpose.SignInGoogle => ParameterUtilities.SignInGoogleParamterPriority[Name],
                RequestPurpose.Token => ParameterUtilities.AuthCodeTokenParamterPriority[Name],
                RequestPurpose.OfflineAccess => ParameterUtilities.OfflineAccessTokenParamterPriority[Name],
                RequestPurpose.ChangePassword => ParameterUtilities.ChangePasswordParamterPriority[Name],
                _ => throw new InvalidDataException($"{Name} : Parameter priority is not set!")
            };
        }
    }

    internal static class ParameterUtilities
    {
        internal static Dictionary<string, Func<string, string, string>> SpecificMethodForInitiatingParameter = new Dictionary<string, Func<string, string, string>>()
        {
            { AuthorizeRequest.Scope, (str, str1) => { return Uri.UnescapeDataString(str); } },
            { AuthorizeRequest.RedirectUri, (str, str1) => { return Uri.UnescapeDataString(str); } },
            { AuthorizeRequest.ResponseMode, (responseMode, responseType) =>
            {
                return string.IsNullOrEmpty(responseMode) ? GetDefaultResponseModeByResponseType(responseType) : responseMode;
            }},
            { RegisterRequest.FirstName, (str, str1) => { return HttpUtility.UrlDecode(str); } },
            { RegisterRequest.LastName, (str, str1) => { return HttpUtility.UrlDecode(str); } }
        };

        internal static Dictionary<string, ParameterPriority> AuthCodeParameterPriority = new Dictionary<string, ParameterPriority>()
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
            { AuthorizeRequest.IdTokenHint, ParameterPriority.OPTIONAL }
        };

        internal static Dictionary<string, ParameterPriority> RegisterParamterPriority = new Dictionary<string, ParameterPriority>()
        {
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
            { SignInGoogleRequest.ClientSecret, ParameterPriority.REQRUIRED },
            { SignInGoogleRequest.ClientId, ParameterPriority.REQRUIRED },
            { SignInGoogleRequest.CodeVerifier, ParameterPriority.OPTIONAL }
            //{ SignInGoogleRequest.Nonce, ParameterPriority.OPTIONAL },
        };

        public static Dictionary<Type, RequestPurpose> ParametersForRequest = new Dictionary<Type, RequestPurpose>()
        {
            { typeof(AuthCodeParameters), RequestPurpose.AuthorizationCode },
            { typeof(RegisterParameters), RequestPurpose.Register },
            // TODO: will add later
            //{ typeof(TokenParameters), RequestType.Token },
            { typeof(SignInGoogleParameters), RequestPurpose.SignInGoogle },
            { typeof(AuthCodeTokenParameters), RequestPurpose.Token },
            { typeof(OfflineAccessTokenParameters), RequestPurpose.OfflineAccess },
            { typeof(ChangePasswordParameters), RequestPurpose.ChangePassword },
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

        private static string GetDefaultResponseModeByResponseType(string responseType)
        {
            string responseMode = "";

            // get grant type for response type
            string grantType = ResponseTypeToGrantTypeMapping[responseType];
            // map grant type with allowed response mode
            string[] responseModes = AllowedResponseModesForGrantType[grantType].ToArray();

            // TODO: by default
            if (responseType.Equals(ResponseTypes.Code))
                responseMode = responseModes.First(m => m.Equals(ResponseModes.Query));
            else if (responseType.Equals(ResponseTypes.Token))
                responseMode = responseModes.First(m => m.Equals(ResponseModes.Fragment));


            return responseMode;
        }
    }

    public enum ParameterPriority
    {
        OPTIONAL,
        REQRUIRED,
        RECOMMENDED
    }
}
