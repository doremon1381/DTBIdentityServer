namespace IssuerOfClaims.Models
{
    public class CustomException : Exception
    {
        public ExceptionIssueToward ExceptionIssueToward { get; private set; }
        public int StatusCode { get; private set; }
        public CustomException(int statusCode, string message, ExceptionIssueToward exceptionIssueToward = ExceptionIssueToward.UserAgent)
            : base(message)
        {
            ExceptionIssueToward = exceptionIssueToward;
            StatusCode = statusCode;
        }
    }

    public enum ExceptionIssueToward
    {
        Local,
        UserAgent
    }
}
