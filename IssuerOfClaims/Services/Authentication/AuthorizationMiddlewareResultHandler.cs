using IssuerOfClaims.Extensions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Policy;
using ServerUltilities.Extensions;
using System.Net;
using static ServerUltilities.Identity.Constants;

namespace IssuerOfClaims.Services.Authentication
{
    public class AuthorizationMiddlewareResultHandler : IAuthorizationMiddlewareResultHandler
    {
        public async Task HandleAsync(RequestDelegate next, HttpContext context, AuthorizationPolicy policy, PolicyAuthorizationResult authorizeResult)
        {
            // TODO: return an error response for authorization endpoint has Authentication header
            if (context.Request.Path.Equals(ProtocolRoutePaths.Authorize)
                && context.Response.StatusCode == (int)HttpStatusCode.BadRequest)
            {
                await context.Response.WriteAsync(ExceptionMessage.AUTHORIZATION_BASIC_NOT_SUPPORT_IN_AUTHORIZE_ENDPOINT);
                await context.Response.CompleteAsync();
                return;
            }
            else if (context.Response.StatusCode == (int)HttpStatusCode.Unauthorized)
            {
                await context.Response.WriteAsync(ExceptionMessage.AUTHENTICATION_INFORMATION_MISSING_OR_MISMATCH);
                await context.Response.CompleteAsync();
                return;
            }
            else
                await next(context);
        }
    }
}
