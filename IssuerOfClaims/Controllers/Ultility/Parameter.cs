using IssuerOfClaims.Extensions;
using ServerUltilities.Identity;
using System.Web;
using static ServerUltilities.Identity.Constants;
using static ServerUltilities.Identity.OidcConstants;

namespace IssuerOfClaims.Controllers.Ultility
{
    public class Parameter
    {
        public string Name { get; private set; } = string.Empty;
        public string Value { get; private set; } = string.Empty;

        public ParameterPriority Priority { get; private set; } = ParameterPriority.OPTIONAL;

        public bool HasValue => !string.IsNullOrEmpty(this.Value);

        public Parameter(string name)
        {
            this.Name = name;
            SetParameterPriority();
        }

        public void SetValue(string value)
        {
            VerifyRequiredParameter(value);
            this.Value = value;
        }

        private bool VerifyRequiredParameter(string value)
        {
            if (this.Priority == ParameterPriority.REQRUIRED)
            {
                if (string.IsNullOrEmpty(value))
                    throw new InvalidDataException($"{this.Name} : {ExceptionMessage.REQUIRED_PARAMETER_NOT_NULL}");
            }

            return true;
        }

        private void SetParameterPriority()
        {
            if (ParameterExtensions.DefaultParameterPriority.ContainsKey(this.Name))
            {
                this.Priority = ParameterExtensions.DefaultParameterPriority[this.Name];
            }
            else if (ParameterExtensions.RegisterParamterPriority.ContainsKey(this.Name))
            {
                this.Priority = ParameterExtensions.RegisterParamterPriority[this.Name];
            }
            else
            {
                throw new InvalidDataException($"{this.Name} : Parameter priority is not set!");
            }
        }
    }

    internal static class ParameterExtensions
    {
        internal static Dictionary<string, ParameterPriority> DefaultParameterPriority = new Dictionary<string, ParameterPriority>()
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

        internal static Dictionary<string, Func<string, string, string>> OAuth2ParameterWithSpecialInitiate = new Dictionary<string, Func<string, string, string>>()
        {
            { AuthorizeRequest.Scope, (str, str1) => { return System.Uri.UnescapeDataString(str); } },
            { AuthorizeRequest.RedirectUri, (str, str1) => { return System.Uri.UnescapeDataString(str); } },
            { AuthorizeRequest.ResponseMode, (responseMode, responseType) => 
            {
                return string.IsNullOrEmpty(responseMode) ? GetDefaultResponseModeByResponseType(responseType) : responseMode;
            }},
            { RegisterRequest.FirstName, (str, str1) => { return HttpUtility.UrlDecode(str); } },
            { RegisterRequest.LastName, (str, str1) => { return HttpUtility.UrlDecode(str); } }
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


        private static string GetDefaultResponseModeByResponseType(string responseType)
        {
            string responseMode = "";

            // get grant type for response type
            string grantType = Constants.ResponseTypeToGrantTypeMapping[responseType];
            // map grant type with allowed response mode
            string[] responseModes = Constants.AllowedResponseModesForGrantType[grantType].ToArray();

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

    public class CustomException : Exception
    {
        public ExceptionIssueToward ExceptionIssueToward { get; private set; }
        public int StatusCode { get; private set; }
        public CustomException(int statusCode, string message, ExceptionIssueToward exceptionIssueToward = ExceptionIssueToward.UserAgent)
            : base(message)
        {
            ExceptionIssueToward = exceptionIssueToward;
            StatusCode = statusCode;
        }
    }

    public enum ExceptionIssueToward
    {
        Local,
        UserAgent
    }
}
