using IssuerOfClaims.Models;
using System.Diagnostics;
using System.Net;
using System.Text;

namespace IssuerOfClaims.Services.Middleware
{
    public class RedirectAuthenticationMiddleware : AbstractMiddleware
    {
        private readonly WebSigninSettings _webSigninSettings;

        public RedirectAuthenticationMiddleware(RequestDelegate @delegate, WebSigninSettings webSigninSettings) : base(@delegate)
        {
            _webSigninSettings = webSigninSettings;
        }

        public override async Task Invoke(HttpContext context)
        {
            if (context.Response.StatusCode == (int)HttpStatusCode.Unauthorized)
            {
                string query = CreateRedirectRequestQuery(context);

                // redirect to login 
                await RedirectToLoginAsync(_webSigninSettings.Origin, query);
                // TODO: terminate request, will check again
                context.Response.StatusCode = (int)HttpStatusCode.OK;
                return;
            }
            else
                await _next(context);
        }

        private static string CreateRedirectRequestQuery(HttpContext context)
        {
            StringBuilder query = new StringBuilder();
            query.Append($"{QS.Path}{QS.Equal}{Uri.EscapeDataString(context.Request.Path.Value)}");
            query.Append($"{QS.And}{QS.Method}{QS.Equal}" + context.Request.Method);
            foreach (var item in context.Request.Query)
            {
                query.Append($"&{item.Key}={item.Value}");
            }

            return query.ToString();
        }

        //TODO: temporary
        private static async Task RedirectToLoginAsync(string loginUri, string query)
        {
            Process.Start(new ProcessStartInfo()
            {
                FileName = string.Format("{0}/?{1}", loginUri, query),
                UseShellExecute = true
            });
        }

        /// <summary>
        /// Query symbols
        /// </summary>
        private static class QS
        {
            public const string Path = "path";
            public const string Equal = "=";
            public const string Method = "method";
            public static string And = "&";
        }
    }
}
