using IssuerOfClaims.Extensions;
using IssuerOfClaims.Models;
using System.Diagnostics;
using System.Net;
using System.Text;
using static ServerUltilities.Identity.Constants;

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
            // TODO: for now, only allow oauth2/authorize enpoint to be redirect if has 401 error after verify authentication header of request, I will think about it later
            string endpoint = context.Request.Path.Value;
            if (endpoint == ProtocolRoutePaths.Authorize)
                if (context.Response.StatusCode == (int)HttpStatusCode.Unauthorized)
                {
                    // TODO: I still want if there is any exception, parent thread will catch it
                    //     : so I want to wait for a task, not the function inside it, which is run on another thread and know nothing about parent of the task
                    await Task.Run(() => RedirectToLoginAsync(context.Request.Path.Value, context.Request.Method, context.Request.Query))
                        .ConfigureAwait(false);

                    // TODO: will check again
                    context.Response.StatusCode = (int)HttpStatusCode.OK;
                    // TODO: terminate request, will check again
                    return;
                }

            await _next(context);

            // TODO: wait for controller doing its work.
        }

        private async Task RedirectToLoginAsync(string path, string method, IQueryCollection queryCollection)
        {
            var query = await Task.Run(() => CreateRedirectRequestQuery(path, method, queryCollection));

            // redirect to login 
            await Task.Run(() => SendRequestAsync(_webSigninSettings.Origin, query)).ConfigureAwait(false);
        }

        private static string CreateRedirectRequestQuery(string path, string method, IQueryCollection queryCollection)
        {
            StringBuilder query = new StringBuilder();
            query.Append($"{QS.Path}{QS.Equal}{Uri.EscapeDataString(path)}");
            //query.Append($"{QS.And}{QS.OauthEndpoint}{QS.Equal}{context.Request.RouteValues.First().Value}");
            query.Append($"{QS.And}{QS.Method}{QS.Equal}" + method);
            foreach (var item in queryCollection)
            {
                query.Append($"&{item.Key}={item.Value}");
            }

            return query.ToString();
        }

        //TODO: temporary
        private static void SendRequestAsync(string loginUri, string query)
        {
            Process.Start(new ProcessStartInfo()
            {
                FileName = string.Format("{0}/?{1}", loginUri, query),
                UseShellExecute = true
            });
        }
    }
}
