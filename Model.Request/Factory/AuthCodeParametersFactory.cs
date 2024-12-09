using IssuerOfClaims.Models.Request.RequestParameter;
using Microsoft.AspNetCore.Http;
using ServerUltilities;
using static ServerUltilities.Identity.OidcConstants;

namespace IssuerOfClaims.Models.Request.Factory
{
    public class AuthCodeParametersFactory : RequestParametersFactory<AuthCodeParameters>
    {
        public AuthCodeParametersFactory(string? queryString) : base(queryString)
        {
        }

        public override AuthCodeParameters ExtractParametersFromQuery(IHeaderDictionary headers = null)
        {
            var obj = (AuthCodeParameters)Constructor.Invoke(null) ?? throw new CustomException("Exception message is not defined!");

            SetResponseTypeFirst(obj, out string responseTypeValue);
            ThenSetResponseMode(obj, responseTypeValue);

            // programaticaly set another parameter values
            base.InitiateProperties(obj);

            QueryParametersValidation.ValidateAuthCodeParameters(obj);

            return obj;
        }

        private void SetResponseTypeFirst(IRequestParameters obj, out string responseTypeValue)
        {
            var responseTypePropertyInfo = PropertiesOfType.First(p => p.Name == nameof(AuthorizeRequest.ResponseType));

            SetPropertyValue(obj, responseTypePropertyInfo);
            var responseType = responseTypePropertyInfo.GetValue(obj, null)
                ?? throw new CustomException($"{nameof(SetResponseTypeFirst)}: null parameters");

            var parameter = (Parameter)responseType;

            // TODO:
            responseTypeValue = parameter.Value ?? throw new CustomException("Somehow...");

            // Because this parameter is created manually
            PropertiesOfType.Remove(responseTypePropertyInfo);
        }

        public void ThenSetResponseMode(IRequestParameters @object, string responseTypeValue)
        {
            var responseMode = PropertiesOfType.First(p => p.Name == nameof(AuthorizeRequest.ResponseMode));
            string value = QueryParameters.GetValue(responseMode.Name);

            var parameter = new Parameter(AuthorizeRequest.ResponseMode, OauthRequestType);

            if (ParameterExtensions.SpecificMethodForInitiatingParameter.TryGetValue(AuthorizeRequest.ResponseMode, out Func<string, string, string> execute))
            {
                value = execute.Invoke(value, responseTypeValue);
            }

            parameter.SetValue(value);
            responseMode.SetValue(@object, parameter);

            // Because this parameter is created manually
            PropertiesOfType.Remove(responseMode);
        }
    }
}
