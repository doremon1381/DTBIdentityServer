namespace IssuerOfClaims.Models.Request.RequestParameter
{
    public class ChangePasswordParameters : IRequestParameters
    {
        public Parameter Code { get; private set; }
        public Parameter NewPassword { get; private set; }
        public Parameter ClientId { get; private set; }

        public ChangePasswordParameters(string? queryString)
        {
        }
    }
}
