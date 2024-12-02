using IssuerOfClaims.Models.Request.RequestParameter;
using Microsoft.AspNetCore.Http;

namespace IssuerOfClaims.Models.Request.Factory
{
    public class ForgotPasswordParametersFactory : RequestParametersFactory<ForgotPasswordParameters>
    {
        public ForgotPasswordParametersFactory(string? queryString) : base(queryString)
        {
        }

        public override ForgotPasswordParameters ExtractParametersFromQuery(IHeaderDictionary headers = null)
        {
            return (ForgotPasswordParameters)base.ExtractParametersFromQuery(headers);
        }
    }
}
