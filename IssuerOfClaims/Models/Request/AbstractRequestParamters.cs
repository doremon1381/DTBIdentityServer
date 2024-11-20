using IssuerOfClaims.Extensions;
using System.Linq.Expressions;
using System.Net;
using System.Reflection;
using static ServerUltilities.Identity.Constants;
using static ServerUltilities.Identity.OidcConstants;

namespace IssuerOfClaims.Models.Request
{
    public abstract class AbstractRequestParamters<T>
    {
        private readonly RequestParameterValues _queryParameters;

        private static readonly Type _currentType = typeof(T);
        private static readonly OauthRequest _oauthRequest = ParameterExtensions.ParametersForRequest[_currentType];

        private static readonly Type _registerRequestType = typeof(RegisterRequest);
        private static readonly Type _authorizeRequestType = typeof(AuthorizeRequest);
        private static readonly Type _signInGoogleRequestType = typeof(SignInGoogleRequest);
        private static readonly Type _changePasswordRequestType = typeof(ChangePasswordRequest);
        private static readonly Type _forgotPasswordRequestType = typeof(ForgotPasswordRequest);
        private static readonly Type _tokenRequestType = typeof(TokenRequest);

        private static readonly string _responseTypeName = nameof(AuthorizeRequest.ResponseType);

        private static readonly FieldInfo[] _parameterNames = _currentType.Name switch
        {
            nameof(AuthCodeParameters) => _authorizeRequestType.GetFields(
                // Gets all public and static fields
                BindingFlags.Public | BindingFlags.Static |
                // This tells it to get the fields from all base types as well
                BindingFlags.FlattenHierarchy),
            nameof(RegisterParameters) => Array.FindAll(_registerRequestType.GetFields(
                // Gets all public and static fields
                BindingFlags.Public | BindingFlags.Static |
                // This tells it to get the fields from all base types as well
                BindingFlags.FlattenHierarchy), (i) => RegisterParameters_MatchPredicate(i.Name)),
            nameof(SignInGoogleParameters) => _signInGoogleRequestType.GetFields(
                BindingFlags.Public | BindingFlags.Static),
            nameof(AuthCodeTokenParameters) => _tokenRequestType.GetFields(
                BindingFlags.Public | BindingFlags.Static),
            nameof(OfflineAccessTokenParameters) => _tokenRequestType.GetFields(
                BindingFlags.Public | BindingFlags.Static),
            nameof(ChangePasswordParameters) => _changePasswordRequestType.GetFields(
                BindingFlags.Public | BindingFlags.Static),
            nameof(ForgotPasswordParameters) => _forgotPasswordRequestType.GetFields(
                BindingFlags.Public | BindingFlags.Static),
            // TODO: will check it later
            _ => throw new InvalidOperationException()
        };

        private static readonly PropertyInfo[] _properties = _currentType.Name switch
        {
            nameof(AuthCodeParameters) => GetProperties(_currentType),
            nameof(RegisterParameters) => Array.FindAll(GetProperties(_currentType), (i) => RegisterParameters_MatchPredicate(i.Name)),
            nameof(SignInGoogleParameters) => GetProperties(_currentType),
            nameof(AuthCodeTokenParameters) => GetProperties(_currentType),
            nameof(OfflineAccessTokenParameters) => GetProperties(_currentType),
            nameof(ChangePasswordParameters) => GetProperties(_currentType),
            nameof(ForgotPasswordParameters) => GetProperties(_currentType),
            // TODO: will check it later
            _ => throw new InvalidOperationException()
        };
        private static readonly PropertyInfo _responseType = _properties.FirstOrDefault(t => t.Name.Equals("ResponseType"));


        public AbstractRequestParamters(string queryString)
        {
            ValidateRequestQuery(queryString);
            _queryParameters = new RequestParameterValues(queryString);

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
            // TODO: for currently logic, to ensure response mode is set after response type, I run this function first
            if (_currentType.Name.Equals(nameof(AuthCodeParameters))
                && _responseType != null)
                SetPropertyValue(_responseType);

            var tasks = _properties.Select(p =>
            {
                if (p.Name.Equals(_responseTypeName))
                    return Task.Run(() => { });
                else
                    return Task.Run(() =>
                    {
                       SetPropertyValue(p);
                    });
            });

            Task.WaitAll(tasks.ToArray());
        }

        /// <summary>
        /// TODO: will have the situation when response type = null while setting value for response mode
        /// </summary>
        /// <param name="setValue"></param>
        /// <param name="property"></param>
        /// <returns></returns>
        private void SetPropertyValue(PropertyInfo property)
        {
            string parameterName = GetNameOfRequestParameter(property.Name);
            string value = _queryParameters.GetValue(parameterName);
            var parameter = new Parameter(parameterName, _oauthRequest);

            if (ParameterExtensions.SpecificMethodForInitiatingParameter.TryGetValue(parameterName, out Func<string, string, string> execute))
            {
                if (parameterName.Equals(AuthorizeRequest.ResponseMode))
                {
#pragma warning disable CS8600 // Converting null literal or possible null value to non-nullable type.
#pragma warning disable CS8602 // Dereference of a possibly null reference.
                    var responseType = (Parameter)_properties
                        .FirstOrDefault(p => p.Name.Equals(_responseTypeName))
                        .GetValue(this, null);
#pragma warning restore CS8602 // Dereference of a possibly null reference.
#pragma warning restore CS8600 // Converting null literal or possible null value to non-nullable type.
                    value = execute.Invoke(value, responseType.Value);
                }
                else
                    value = execute.Invoke(value, string.Empty);
            }

            parameter.SetValue(value);
            property.SetValue(this, parameter);
        }

        private static string GetNameOfRequestParameter(string propertyName)
        {
            var name = _parameterNames.FirstOrDefault(p => p.Name.ToUpper().Equals(propertyName.ToUpper()));
            var n = (string)name.GetValue(null);
            return n;
        }

        /// <summary>
        /// TODO: will modify this function later
        /// </summary>
        /// <returns></returns>
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
                throw new CustomException(ExceptionMessage.QUERYSTRING_NOT_NULL_OR_EMPTY, HttpStatusCode.BadRequest);
        }
    }

    public enum OauthRequest
    {
        AuthorizationCode,
        Token,
        Register,
        SignInGoogle,
        OfflineAccess,
        ChangePassword,
        ForgotPassword
    }
}
