using IssuerOfClaims.Extensions;
using ServerUltilities.Extensions;
using System.Linq.Expressions;
using System.Reflection;
using System.Web;
using static ServerUltilities.Identity.Constants;
using static ServerUltilities.Identity.OidcConstants;

namespace IssuerOfClaims.Controllers.Ultility
{
    public abstract class AbtractRequestParamters<T>
    {
        protected readonly string[] requestQuery;

        private static readonly Type _currentType = typeof(T);
        private static readonly Type _registerRequestType = typeof(RegisterRequest);
        private static readonly Type _authorizeRequestType = typeof(AuthorizeRequest);

        private static readonly FieldInfo[] _parameterNames = _currentType.Name switch
        {
            nameof(Oauth2Parameters) => _authorizeRequestType.GetFields(
                // Gets all public and static fields
                BindingFlags.Public | BindingFlags.Static |
                // This tells it to get the fields from all base types as well
                BindingFlags.FlattenHierarchy),
            nameof(RegisterParameters) => Array.FindAll(_registerRequestType.GetFields(
                // Gets all public and static fields
                BindingFlags.Public | BindingFlags.Static |
                // This tells it to get the fields from all base types as well
                BindingFlags.FlattenHierarchy), (i) => RegisterParameters_MatchPredicate(i.Name)),
            // TODO: will check it later
            _ => throw new InvalidOperationException()
        };

        private static readonly PropertyInfo[] _properties = _currentType.Name switch 
        {
            nameof(Oauth2Parameters) => GetProperties(_currentType),
            nameof(RegisterParameters) => Array.FindAll(GetProperties(_currentType), (i) => RegisterParameters_MatchPredicate(i.Name)),
            // TODO: will check it later
            _ => throw new InvalidOperationException()
        };

        private static readonly PropertyInfo _responseType = _properties.FirstOrDefault(t => t.Name.Equals("ResponseType"));

        public AbtractRequestParamters(string? queryString)
        {
            requestQuery = QueryStringToArray(queryString);

            InitiateProperties();
        }

        private static PropertyInfo[] GetProperties(Type type)
        {
            return type.GetProperties().Where(p => p.PropertyType.Equals(typeof(Parameter))).ToArray();
        }

        private static bool RegisterParameters_MatchPredicate(string name)
        {
            // TODO: special case
            if (name == RegisterRequest.UserName
                || name == RegisterRequest.Password)
                return false;
            return true;
        }

        private void InitiateProperties()
        {
            Action<Parameter, string> setValueMethod = FunctionToInitiateValueOfProperty();

            // TODO: for currently logic, to ensure response mode is set, I run this function first
            if (_responseType != null)
                Task.Run(async () => { await SetPropertyValueAsync(setValueMethod, _responseType); }).Wait();

            List<Task> tasks = new List<Task>();
            foreach (var property in _properties)
            {
                if (property.Name.Equals("ResponseType"))
                    continue;
                else
                    tasks.Add(Task.Run(async () =>
                    {
                        await SetPropertyValueAsync(setValueMethod, property);
                    }));
            }
            Task.WaitAll(tasks.ToArray());
        }

        /// <summary>
        /// TODO: will have the situation when response type = null while setting value for response mode
        /// </summary>
        /// <param name="setValue"></param>
        /// <param name="property"></param>
        /// <returns></returns>
        private async Task SetPropertyValueAsync(Action<Parameter, string> setValue, PropertyInfo property)
        {
            string mappingName = GetMappingNameForRequestParameter(property.Name);
            string parameterValue = requestQuery.GetFromQueryString(mappingName);

            var parameter = new Parameter(mappingName);

            if (ParameterExtensions.OAuth2ParameterWithSpecialInitiate.TryGetValue(mappingName, out Func<string, string, string> execute))
            {
                if (mappingName.Equals(AuthorizeRequest.ResponseMode))
                {
#pragma warning disable CS8600 // Converting null literal or possible null value to non-nullable type.
#pragma warning disable CS8602 // Dereference of a possibly null reference.
                    var responseType = (Parameter)_properties
                        .FirstOrDefault(p => p.Name.Equals("ResponseType"))
                        .GetValue(this, null);
#pragma warning restore CS8602 // Dereference of a possibly null reference.
#pragma warning restore CS8600 // Converting null literal or possible null value to non-nullable type.
                    parameterValue = execute.Invoke(parameterValue, responseType.Value);
                }
                else
                    parameterValue = execute.Invoke(parameterValue, string.Empty);
            }

            setValue(parameter, parameterValue);
            property.SetValue(this, parameter);
        }

        private static string GetMappingNameForRequestParameter(string propertyName)
        {
            var name = _parameterNames.FirstOrDefault(p => p.Name.Equals(propertyName));
            var n = (string)name.GetValue(null);
            return n;
        }

        private static Action<Parameter, string> FunctionToInitiateValueOfProperty()
        {
            MethodInfo setValue = typeof(Parameter).GetMethod("SetValue", new[] { typeof(string) });
            ParameterExpression instance = Expression.Parameter(typeof(Parameter), "x");
            ParameterExpression param = Expression.Parameter(typeof(string), "y");

            Expression call = Expression.Call(instance, setValue, param);

            Expression<Action<Parameter, string>> methodHander = Expression.Lambda<Action<Parameter, string>>(call, instance, param);
            var method = methodHander.Compile();

            return method;
        }

        private static void ValidateRequestQuery(string? requestQuery)
        {
            if (string.IsNullOrEmpty(requestQuery))
                throw new CustomException(400, ExceptionMessage.QUERYSTRING_NOT_NULL_OR_EMPTY);
        }

        private static string[] QueryStringToArray(string? queryString)
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
