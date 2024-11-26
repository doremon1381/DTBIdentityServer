using IssuerOfClaims.Extensions;
using IssuerOfClaims.Models;
using ServerUltilities;
using System.Net;
using System.Text;
using static ServerUltilities.Identity.Constants;
using static ServerUltilities.Identity.OidcConstants;

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
            try
            {
                // TODO: for now, only allow oauth2/authorize enpoint to be redirect if has 401 error after verify authentication header of request, I will think about it later
                string endpoint = context.Request.Path.Value;

                if (endpoint.Equals(ProtocolRoutePaths.Authorize))
                    if (context.Response.StatusCode == (int)HttpStatusCode.Unauthorized)
                    {
                        string requestPath = context.Request.Path.Value;
                        string method = context.Request.Method;
                        var query = context.Request.Query;

                        // TODO: I still want if there is any exception, parent thread will catch it
                        //     : so I want to wait for a task, not the function inside it, which is run on another thread and know nothing about parent of the task
                        var queryString = await Task.Run(() => CreateRedirectRequestQuery(requestPath, method, query));

                        // TODO: will check again
                        context.Response.Redirect(string.Format("{0}?{1}", _webSigninSettings.SigninUri, queryString));
                        // TODO: immediately response, will check again
                        return;
                    }

                await _next(context);
            }
            catch (Exception ex)
            {
                throw new Exception($"{nameof(RedirectAuthenticationMiddleware)}: {ex.Message}");
            }
        }

        private static string CreateRedirectRequestQuery(string path, string method, IQueryCollection queryCollection)
        {
            StringBuilder query = new StringBuilder();
            query.Append($"{QS.Path}{QS.Equal}{Uri.EscapeDataString(path)}");
            query.Append($"{QS.And}{QS.Flow}{QS.Equal} {GetMappingFlow(queryCollection)}");
            query.Append($"{QS.And}{QS.Method}{QS.Equal}" + method);
            foreach (var item in queryCollection)
            {
                // TODO: format string if acceptable
                query.Append($"&{item.Key.ToLower()}={item.Value}");
            }

            return query.ToString();
        }

        private static string GetMappingFlow(IQueryCollection queryCollection)
        {
            var responeType = queryCollection.FirstOrDefault(q => q.Key.ToUpper().Equals(AuthorizeRequest.ResponseType.ToUpper()));

            if (string.IsNullOrEmpty(responeType.Value))
                throw new CustomException("Authentication for request is not accepted!");

            return ResponseTypeToGrantTypeMapping[responeType.Value];
        }
    }
}
