using IssuerOfClaims.Extensions;
using ServerUltilities.Extensions;
using System.Web;
using static ServerUltilities.Identity.Constants;
using static ServerUltilities.Identity.OidcConstants;

namespace IssuerOfClaims.Controllers.Ultility
{
    public abstract class AbtractRequestParamters
    {
        protected readonly string[] requestQuery;

        //public List<Parameter> Parameters { get; private set; } = new List<Parameter>();

        public AbtractRequestParamters(string? queryString)
            //, RequestType requestType)
        {
            requestQuery = QueryStringToArray(queryString);

            //Parameters.AddRange(RequestParametersExtensions.ParametersForRequestType[requestType].Select((name) =>
            //{
            //    var param = new Parameter(name);
            //    string value = requestQuery.GetFromQueryString(name);
            //    if (RequestParametersExtensions.InitiateForParameters.ContainsKey(name))
            //        value = RequestParametersExtensions.InitiateForParameters[name](value);

            //    param.SetValue(value);

            //    return param;
            //}));
        }

        private void ValidateRequestQuery(string? requestQuery)
        {
            if (string.IsNullOrEmpty(requestQuery))
                throw new CustomException(400, ExceptionMessage.QUERYSTRING_NOT_NULL_OR_EMPTY);
        }

        private string[] QueryStringToArray(string? queryString)
        {
            ValidateRequestQuery(queryString);

            return queryString.Remove(0, 1).Split("&");
        }
    }

    public static class RequestParametersExtensions
    {
        public static Dictionary<RequestType, List<string>> ParametersForRequestType = new Dictionary<RequestType, List<string>>()
        {
            { RequestType.Authorization, new List<string>()
                {
                    AuthorizeRequest.Scope, AuthorizeRequest.Nonce, AuthorizeRequest.Prompt,
                    AuthorizeRequest.State, AuthorizeRequest.Nonce, AuthorizeRequest.ClientId,
                    AuthorizeRequest.RedirectUri, AuthorizeRequest.CodeChallenge, AuthorizeRequest.CodeChallengeMethod,
                    AuthorizeRequest.ResponseType, AuthorizeRequest.ResponseMode
                }
            },
            { RequestType.Register, new List<string>()
                {
                    RegisterRequest.State, RegisterRequest.RedirectUri, RegisterRequest.ClientId,
                    RegisterRequest.UserName, RegisterRequest.Password, RegisterRequest.Nonce,
                    RegisterRequest.Email, RegisterRequest.FirstName, RegisterRequest.LastName,
                    RegisterRequest.Roles, RegisterRequest.Gender
                }
            }
        };

        // TODO: name of parameter and initiate function
        public static Dictionary<string, Func<string, string>> InitiateForParameters = new Dictionary<string, Func<string, string>>()
        {
            { AuthorizeRequest.Scope, (value) => System.Uri.UnescapeDataString(value) },
            { "redirect_uri", (value) => System.Uri.UnescapeDataString(value) },
            { RegisterRequest.FirstName, (value) => HttpUtility.UrlDecode(value).TrimStart().TrimEnd() },
            { RegisterRequest.LastName, (value) => HttpUtility.UrlDecode(value).TrimStart().TrimEnd() }
        };
    }

    public enum RequestType
    {
        Authorization,
        Token,
        Register
    }
}
