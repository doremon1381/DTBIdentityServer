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
        protected static readonly OauthRequestType OauthRequestType = ParameterExtensions.ParametersForRequest[typeof(T)];
        /// <summary>
        /// constructor by default does not have any parameter
        /// </summary>
        protected static readonly ConstructorInfo Constructor = typeof(T).GetConstructor(new Type[] { }) 
            ?? throw new CustomException($"{nameof(RequestParametersFactoryBase<T>)}: An error occurs during generic type's constructor creation!");
        protected List<PropertyInfo> PropertiesOfType { get; set; } = new List<PropertyInfo>(typeof(T).GetProperties().Where(p => p.PropertyType.Equals(typeof(Parameter))));

        /// <summary>
        /// TODO: need to be implemented!
        /// </summary>
        /// <param name="headers"></param>
        /// <returns></returns>
        /// <exception cref="NotImplementedException"></exception>
        public virtual IRequestParameters ExtractParametersFromQuery(IHeaderDictionary headers = null)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// TODO: need to be implemented!
        /// </summary>
        /// <param name="requestParameters"></param>
        /// <exception cref="NotImplementedException"></exception>
        protected virtual void InitiateProperties(IRequestParameters requestParameters)
        {
            throw new NotImplementedException();
        }
    }

    public abstract class RequestParametersFactory<T> : RequestParametersFactoryBase<T> where T : class, IRequestParameters
    {
        protected RequestParameterValues QueryParameters { get; set; }

        public RequestParametersFactory(string? queryString)
        {
            QueryParameters = new RequestParameterValues(queryString);
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

            var parameter = new Parameter(parameterName, OauthRequestType);

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
