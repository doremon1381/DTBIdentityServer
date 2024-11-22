using System.Net;

namespace ServerUltilities
{
    public class CustomException : Exception
    {
        public ExceptionIssueToward ExceptionIssueToward { get; private set; }
        public HttpStatusCode StatusError { get; private set; }
        /// <summary>
        /// 
        /// </summary>
        /// <param name="message"></param>
        /// <param name="statusCode">By default, it's internal server error</param>
        /// <param name="exceptionIssueToward"></param>
        public CustomException(string message, HttpStatusCode statusCode = HttpStatusCode.InternalServerError, ExceptionIssueToward exceptionIssueToward = ExceptionIssueToward.UserAgent)
            : base(message)
        {
            ExceptionIssueToward = exceptionIssueToward;
            StatusError = statusCode;
        }

        internal int StatusCode => (int)this.StatusError;
    }

    public enum ExceptionIssueToward
    {
        Local,
        UserAgent
    }
}
