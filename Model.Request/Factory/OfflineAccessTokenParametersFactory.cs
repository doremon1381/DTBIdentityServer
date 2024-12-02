using IssuerOfClaims.Models.Request.RequestParameter;
using Microsoft.AspNetCore.Http;

namespace IssuerOfClaims.Models.Request.Factory
{
    public class OfflineAccessTokenParametersFactory : RequestParametersFactory<OfflineAccessTokenParameters>
    {
        public OfflineAccessTokenParametersFactory(string? queryString) : base(queryString)
        {
        }

        public override OfflineAccessTokenParameters ExtractParametersFromQuery(IHeaderDictionary headers = null)
        {
            return (OfflineAccessTokenParameters)base.ExtractParametersFromQuery(headers);
        }
    }
}
