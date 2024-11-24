using ServerUltilities;
using ServerUltilities.Extensions;
using System.Net;

namespace IssuerOfClaims.Models.Request.RequestParameter
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

        public Parameter(string name, OauthRequest oauthRequest)
        {
            Name = name;
            SetParameterPriority(oauthRequest);
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
                    throw new CustomException($"{Name} : {ExceptionMessage.REQUIRED_PARAMETER_NOT_NULL}", HttpStatusCode.BadRequest);
            }

            return true;
        }

        private void SetParameterPriority(OauthRequest requestType)
        {
            Priority = requestType switch
            {
                OauthRequest.AuthorizationCode => ParameterExtensions.AuthCodeParametersPriority[Name],
                OauthRequest.Register => ParameterExtensions.RegisterParamterPriority[Name],
                OauthRequest.SignInGoogle => ParameterExtensions.SignInGoogleParamterPriority[Name],
                OauthRequest.Token => ParameterExtensions.AuthCodeTokenParamterPriority[Name],
                OauthRequest.OfflineAccess => ParameterExtensions.OfflineAccessTokenParamterPriority[Name],
                OauthRequest.ChangePassword => ParameterExtensions.ChangePasswordParamterPriority[Name],
                OauthRequest.ForgotPassword => ParameterExtensions.ForgotPasswordParamterPriority[Name],
                _ => throw new InvalidDataException($"{Name} : Parameter priority is not set!")
            };
        }
    }
}
