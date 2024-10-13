namespace IssuerOfClaims.Controllers.Ultility
{
    public class AuthCodeTokenParameters : AbstractRequestParamters<AuthCodeTokenParameters>
    {
        public Parameter Code { get; private set; }
        public Parameter ClientId { get; private set; }
        public Parameter ClientSecret { get; private set; }
        public Parameter RedirectUri { get; private set; }
        public Parameter CodeVerifier { get; private set; }
        public Parameter Audience { get; private set; }
        public Parameter Scope { get; private set; }

        public AuthCodeTokenParameters(string? queryString) : base(queryString)
        {
        }
    }

    public class OfflineAccessTokenParameters : AbstractRequestParamters<OfflineAccessTokenParameters>
    {
        public Parameter RefreshToken { get; private set; }
        public Parameter ClientId { get; private set; }
        public Parameter ClientSecret { get; private set; }
        public Parameter Scope { get; private set; }

        public OfflineAccessTokenParameters(string? queryString) : base(queryString)
        {
        }
    }
}
