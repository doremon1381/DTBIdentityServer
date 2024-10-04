using IssuerOfClaims.Extensions;

namespace IssuerOfClaims.Controllers.Ultility
{
    public abstract class AbtractRequestParamters
    {
        protected readonly string[] requestQuery;

        public AbtractRequestParamters(string? queryString)
        {
            requestQuery = QueryStringToArray(queryString);
        }

        private void ValidateRequestQuery(string? requestQuery)
        {
            if (string.IsNullOrEmpty(requestQuery))
                throw new InvalidDataException(ExceptionMessage.QUERYSTRING_NOT_NULL_OR_EMPTY);
        }

        private string[] QueryStringToArray(string? queryString)
        {
            ValidateRequestQuery(queryString);

            return queryString.Remove(0, 1).Split("&");
        }
    }
}
