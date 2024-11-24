namespace IssuerOfClaims.Models.Request.RequestParameter
{
    public class AuthCodeTokenParameters : IRequestParameters
    {
        public Parameter Code { get; private set; }
        public Parameter ClientId { get; private set; }
        public Parameter ClientSecret { get; private set; }
        public Parameter RedirectUri { get; private set; }
        public Parameter CodeVerifier { get; private set; }
        public Parameter Audience { get; private set; }
        public Parameter Scope { get; private set; }

        public AuthCodeTokenParameters()
        {
        }
    }
}
