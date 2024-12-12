using Microsoft.AspNetCore.Http;

namespace IssuerOfClaims.Models.Request.Factory
{
    public class ClientCredentialsParametersFactory : RequestParametersFactory<ClientCredentialsParameters>
    {
        public ClientCredentialsParametersFactory(string? queryString) : base(queryString)
        {
        }

        public override ClientCredentialsParameters ExtractParametersFromQuery(IHeaderDictionary headers = null)
        {
            return (ClientCredentialsParameters) base.ExtractParametersFromQuery(headers);
        }
    }
}
