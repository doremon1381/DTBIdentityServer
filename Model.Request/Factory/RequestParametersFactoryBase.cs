using IssuerOfClaims.Models.Request.RequestParameter;
using Microsoft.AspNetCore.Http;
using ServerUltilities;
using ServerUltilities.Extensions;
using System.Net;
using System.Reflection;

namespace IssuerOfClaims.Models.Request.Factory
{
    public abstract class RequestParametersFactoryBase<T> where T : class, IRequestParameters
    {
        protected static readonly OauthRequest OauthRequest = ParameterExtensions.ParametersForRequest[typeof(T)];
        /// <summary>
        /// constructor by default does not have any parameter
        /// </summary>
        protected static readonly ConstructorInfo Constructor = typeof(T).GetConstructor(new Type[] { });
        protected List<PropertyInfo> PropertiesOfType { get; set; } = new List<PropertyInfo>(typeof(T).GetProperties().Where(p => p.PropertyType.Equals(typeof(Parameter))));

        public abstract IRequestParameters ExtractParametersFromQuery(IHeaderDictionary headers = null);
        protected abstract void InitiateProperties(IRequestParameters requestParameters);
    }

    public abstract class RequestParametersFactory<T> : RequestParametersFactoryBase<T> where T : class, IRequestParameters
    {
        protected RequestParameterValues QueryParameters { get; set; }

        public RequestParametersFactory(string queryString)
        {
            ValidateRequestQuery(queryString);
            QueryParameters = new RequestParameterValues(queryString);
        }

        protected static void ValidateRequestQuery(string? requestQuery)
        {
            if (string.IsNullOrEmpty(requestQuery))
                throw new CustomException(ExceptionMessage.QUERYSTRING_NOT_NULL_OR_EMPTY, HttpStatusCode.BadRequest);
        }


        public override IRequestParameters ExtractParametersFromQuery(IHeaderDictionary headers = null)
        {
            // 1. Create queryParameters value
            // 2. Create object from constructor
            // 3. set object properties value
            IRequestParameters obj = (IRequestParameters)Constructor.Invoke(null) ?? throw new CustomException("Exception message is not defined!");

            InitiateProperties(obj);

            return obj;
        }

        protected override void InitiateProperties(IRequestParameters requestParameters)
        {
            var tasks = PropertiesOfType.Select(p =>
            {
                return Task.Run(() =>
                {
                    SetPropertyValue(requestParameters, p);
                });
            });

            Task.WaitAll(tasks.ToArray());
        }

        protected void SetPropertyValue(IRequestParameters @object, PropertyInfo property)
        {
            string parameterName = GetNameOfRequestParameter(property.Name);
            string value = QueryParameters.GetValue(parameterName);

            var parameter = new Parameter(parameterName, OauthRequest);

            if (ParameterExtensions.SpecificMethodForInitiatingParameter.TryGetValue(parameterName, out Func<string, string, string> execute))
            {
                value = execute.Invoke(value, string.Empty);
            }

            parameter.SetValue(value);
            property.SetValue(@object, parameter);
        }

        protected static string GetNameOfRequestParameter(string propertyName)
        {
            var normalizedName = RequestParameterExtension.ParameterNames(typeof(T)).FirstOrDefault(p => p.Name.ToUpper().Equals(propertyName.ToUpper()));
            
            // TODO:
            var name = (string)normalizedName.GetValue(null) ?? throw new CustomException("");

            return name;
        }
    }
}
