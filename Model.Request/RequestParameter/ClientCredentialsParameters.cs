using IssuerOfClaims.Models.Request.RequestParameter;

namespace IssuerOfClaims.Models.Request
{
    public class ClientCredentialsParameters: IRequestParameters
    {
        public Parameter GrantType { get; private set; }
        public Parameter Scope { get; private set; }
        public Parameter ClientId { get; private set; }
        public Parameter ClientSecret { get; private set; }

        public ClientCredentialsParameters()
        {
            
        }
    }
}
