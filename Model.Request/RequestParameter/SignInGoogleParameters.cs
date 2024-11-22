using static ServerUltilities.Identity.Constants;

namespace IssuerOfClaims.Models.Request.RequestParameter
{
    public class SignInGoogleParameters : IRequestParameters
    {
        public Parameter AuthorizationCode { get; private set; }
        public Parameter RedirectUri { get; private set; }
        public Parameter CodeVerifier { get; private set; }
        public Parameter ClientId { get; private set; }
        public Parameter ClientSecret { get; private set; }

        public SignInGoogleParameters()
        {
        }
    }
}
