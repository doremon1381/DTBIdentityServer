using static ServerUltilities.Identity.Constants;

namespace IssuerOfClaims.Controllers.Ultility
{
    public class SignInGoogleParameters : AbstractRequestParamters<SignInGoogleParameters>
    {
        public Parameter AuthorizationCode { get; private set; }
        public Parameter RedirectUri { get; private set; }
        public Parameter CodeVerifier { get; private set; }
        public Parameter Nonce { get; private set; }

#pragma warning disable CS8618 // Non-nullable field must contain a non-null value when exiting constructor. Consider declaring as nullable.
        public SignInGoogleParameters(string? queryString) : base(queryString)
#pragma warning restore CS8618 // Non-nullable field must contain a non-null value when exiting constructor. Consider declaring as nullable.
        {
        }
    }
}
