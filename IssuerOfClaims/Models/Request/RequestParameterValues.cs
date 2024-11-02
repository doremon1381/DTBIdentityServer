﻿using IssuerOfClaims.Extensions;
using Microsoft.AspNetCore.Http;
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
            TaskUtilities.RunAttachedToParentTask(() => Initiate(queryString)).GetAwaiter().GetResult();
        }

        private void Initiate(string queryString)
        {
            var @params = queryString.RemoveQueryOrFragmentSymbol().Split("&");
            var tasks = new List<Task>();
            foreach (var param in @params)
            {
                tasks.Add(TaskUtilities.RunAttachedToParentTask(async () =>
                {
                    var nameValuePair = param.Split("=");
                    var normalizedName = nameValuePair[0].ToUpper();

                    await _semaphoreSlim.WaitAsync();

                    _ParameterValuePairs.Add(normalizedName, nameValuePair[1]);

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
}
