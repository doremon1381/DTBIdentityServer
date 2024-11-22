using IssuerOfClaims.Models.Request.RequestParameter;
using Microsoft.AspNetCore.Http;

namespace IssuerOfClaims.Models.Request.Factory
{
    public class ChangePasswordParametersFactory : RequestParametersFactory<ChangePasswordParameters>
    {
        public ChangePasswordParametersFactory(string queryString) : base(queryString)
        {
        }

        public override ChangePasswordParameters ExtractParametersFromQuery(IHeaderDictionary headers = null)
        {
            return (ChangePasswordParameters)base.ExtractParametersFromQuery(headers);
        }
    }
}
