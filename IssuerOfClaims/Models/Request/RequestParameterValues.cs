using IssuerOfClaims.Extensions;
using System.Net;

namespace IssuerOfClaims.Models.Request
{
    /// <summary>
    /// The following path of url after question mark (?)
    /// </summary>
    public class RequestParameterValues
    {
        private readonly object @lock = new object();
        private static readonly SemaphoreSlim _semaphoreSlim = new SemaphoreSlim(1, 1);

        private readonly Dictionary<string, string> _ParameterValuePairs = new Dictionary<string, string>();

        public RequestParameterValues(string? queryString)
        {
            Validate(queryString);
            Task.Factory.StartNew(() => InitiateAsync(queryString)).Wait();
        }

        private void InitiateAsync(string queryString)
        {
            var @params = queryString.Remove(0, 1).Split("&");
            foreach (var param in @params)
            {
                Task.Factory.StartNew(async () =>
                {
                    var nameValuePair = param.Split("=");
                    var normalizedName = nameValuePair[0].ToUpper();

                    await _semaphoreSlim.WaitAsync();

                    _ParameterValuePairs.Add(normalizedName, nameValuePair[1]);

                    _semaphoreSlim.Release();

                }, TaskCreationOptions.AttachedToParent).Wait();
            }
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
}
