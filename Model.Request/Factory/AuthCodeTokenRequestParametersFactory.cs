using IssuerOfClaims.Models.Request.RequestParameter;
using Microsoft.AspNetCore.Http;

namespace IssuerOfClaims.Models.Request.Factory
{
    public class AuthCodeTokenRequestParametersFactory : RequestParametersFactory<AuthCodeTokenParameters>
    {
        public AuthCodeTokenRequestParametersFactory(string queryString) : base(queryString)
        {
        }

        public override AuthCodeTokenParameters ExtractParametersFromQuery(IHeaderDictionary headers = null)
        {
            return (AuthCodeTokenParameters)base.ExtractParametersFromQuery(headers);
        }
    }
}
