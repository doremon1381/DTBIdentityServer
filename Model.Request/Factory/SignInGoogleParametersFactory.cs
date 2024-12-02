using IssuerOfClaims.Models.Request.RequestParameter;
using Microsoft.AspNetCore.Http;

namespace IssuerOfClaims.Models.Request.Factory
{
    public class SignInGoogleParametersFactory : RequestParametersFactory<SignInGoogleParameters>
    {
        public SignInGoogleParametersFactory(string? queryString) : base(queryString)
        {
        }

        public override SignInGoogleParameters ExtractParametersFromQuery(IHeaderDictionary headers = null)
        {
            return (SignInGoogleParameters)base.ExtractParametersFromQuery(headers);
        }
    }
}
