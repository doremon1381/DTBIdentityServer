namespace IssuerOfClaims.Models.Request.RequestParameter
{
    public class OfflineAccessTokenParameters : IRequestParameters
    {
        public Parameter RefreshToken { get; private set; }
        public Parameter ClientId { get; private set; }
        public Parameter ClientSecret { get; private set; }
        public Parameter Scope { get; private set; }

        public OfflineAccessTokenParameters()
        {
        }
    }
}
