namespace IssuerOfClaims.Controllers.Ultility
{
    public class ChangePasswordParameters : AbstractRequestParamters<ChangePasswordParameters>
    {
        public Parameter Code { get; private set; }
        public Parameter NewPassword { get; private set; }
        public Parameter ClientId { get; private set; }

        public ChangePasswordParameters(string? queryString) : base(queryString)
        {
        }
    }
}
