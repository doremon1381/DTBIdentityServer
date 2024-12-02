using ServerUltilities;
using ServerUltilities.Extensions;
using System.Net;

namespace IssuerOfClaims.Models.Request.RequestParameter
{
    /// <summary>
    /// The following path of url after question mark (?)
    /// </summary>
    public class RequestParameterValues
    {
        private readonly object @lock = new object();
        private readonly SemaphoreSlim _semaphoreSlim = new SemaphoreSlim(1, 1);

        private readonly Dictionary<string, string> _ParameterValuePairs = new Dictionary<string, string>();

        public RequestParameterValues(string? queryString)
        {
            Validate(queryString);
            TaskUtilities.RunAttachedToParentTask(() => Initiate(queryString)).GetAwaiter().GetResult();
        }

        private void Initiate(string queryString)
        {
            var @params = queryString.ToDictionary();
            var tasks = new List<Task>();
            foreach (var param in @params)
            {
                tasks.Add(Task.Run(async () =>
                {
                    var normalizedName = param.Key.ToUpper();

                    await _semaphoreSlim.WaitAsync();

                    _ParameterValuePairs.Add(normalizedName, param.Value);

                    _semaphoreSlim.Release();

                }));
            }

            Task.WaitAll(tasks.ToArray());
        }

        private bool Validate(string? queryString)
        {
            if (string.IsNullOrEmpty(queryString))
                throw new CustomException(ExceptionMessage.QUERYSTRING_NOT_NULL_OR_EMPTY, HttpStatusCode.BadRequest);
            return true;
        }

        public string GetValue(string parameterName)
        {
            var normalizedName = parameterName.ToUpper();
            return _ParameterValuePairs.GetValueOrDefault(normalizedName) ?? string.Empty;
        }
    }

    public static class RequestParameterExtensions
    {
        private static string _DefaultSeparateSymbol = "&";
        private static string _EqualSymbol = "=";

        /// <summary>
        /// Assuming in auth request, after path, always is a string with form is "{query symbol (?) or fragment symbol (#)}{parameters and value}"
        /// <para>Example: https://server.example.com/authorize?response_type=code&scope=openid%20profile%20email&client_id=s6BhdRkqt3&state=af0ifjsldkj&redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb</para>
        /// </summary>
        /// <param name="queryString"></param>
        /// <returns></returns>
        private static string RemoveQueryOrFragmentSymbol(this string queryString)
        {
            return queryString.Remove(0, 1);
        }

        public static Dictionary<string, string> ToDictionary(this string query)
        {
            // by default, an element's format is "{key}={value}"
            var keyValuePairs = from element in query.RemoveQueryOrFragmentSymbol().Split(_DefaultSeparateSymbol)
                                where element != null
                                let keyValue = element.Split(_EqualSymbol)
                                select new KeyValuePair<string, string>(keyValue[0], keyValue[1]);

            return new Dictionary<string, string>(keyValuePairs);
        }
    }
}
