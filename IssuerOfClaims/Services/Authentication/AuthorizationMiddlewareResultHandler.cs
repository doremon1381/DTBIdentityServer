﻿using IssuerOfClaims.Extensions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Policy;
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
                await context.Response.WriteAsync(ExceptionMessage.AUTHORIZATION_BASIC_NOT_SUPPORT_FOR_AUTHORIZE_ENDPOINT);
                await context.Response.CompleteAsync();
                return;
            }
            else
                await next(context);
        }
    }
}