namespace IssuerOfClaims.Models.Request
{
    public class ForgotPasswordParameters : AbstractRequestParamters<ForgotPasswordParameters>
    {
        public Parameter ClientId { get; set; }
        public Parameter Email { get; set; }

        public ForgotPasswordParameters(string query) : base(query)
        {
        
        }
    }
}
