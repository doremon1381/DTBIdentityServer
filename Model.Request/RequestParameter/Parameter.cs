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

        public Parameter(string name, OauthRequestType oauthRequest)
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

        private void SetParameterPriority(OauthRequestType requestType)
        {
            Priority = requestType switch
            {
                OauthRequestType.AuthorizationCode => ParameterExtensions.AuthCodeParametersPriority[Name],
                OauthRequestType.Register => ParameterExtensions.RegisterParamterPriority[Name],
                OauthRequestType.SignInGoogle => ParameterExtensions.SignInGoogleParamterPriority[Name],
                OauthRequestType.Token => ParameterExtensions.AuthCodeTokenParamterPriority[Name],
                OauthRequestType.OfflineAccess => ParameterExtensions.OfflineAccessTokenParamterPriority[Name],
                OauthRequestType.ChangePassword => ParameterExtensions.ChangePasswordParamterPriority[Name],
                OauthRequestType.ForgotPassword => ParameterExtensions.ForgotPasswordParamterPriority[Name],
                OauthRequestType.ClientCredentials => ParameterExtensions.ClientCredentialsParameterPriority[Name],
                _ => throw new InvalidDataException($"{Name} : Parameter priority is not set!")
            };
        }
    }
}
