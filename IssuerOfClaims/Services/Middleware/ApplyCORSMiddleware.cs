using IssuerOfClaims.Extensions;
using IssuerOfClaims.Models;
using System.Net;

namespace IssuerOfClaims.Services.Middleware
{
    public class ApplyCORSMiddleware : AbstractMiddleware
    {
        private WebSigninSettings _webSigninSettings;

        public ApplyCORSMiddleware(RequestDelegate @delegate, WebSigninSettings webSigninSettings) : base(@delegate)
        {
            _webSigninSettings = webSigninSettings;
        }

        public override async Task Invoke(HttpContext context)
        {
            // TODO: will add another origin if that is need
            context.Response.Headers.AccessControlAllowOrigin = _webSigninSettings.Origin;

            if (context.Request.Method.IsOptions())
            {
                context.Response.Headers.AccessControlAllowMethods = _webSigninSettings.AllowedMethods;
                context.Response.Headers.AccessControlAllowHeaders = "*";
                context.Response.Headers.AccessControlAllowCredentials = "true";

                context.Response.StatusCode = (int)HttpStatusCode.OK;
                await context.Response.CompleteAsync();
            }
            else 
                await _next(context);
        }
    }
}
