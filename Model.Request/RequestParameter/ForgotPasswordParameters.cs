namespace IssuerOfClaims.Models.Request.RequestParameter
{
    public class ForgotPasswordParameters : IRequestParameters
    {
        public Parameter ClientId { get; set; }
        public Parameter Email { get; set; }

        public ForgotPasswordParameters(string query)
        {

        }
    }
}
