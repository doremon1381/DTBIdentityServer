using IssuerOfClaims.Extensions;
using IssuerOfClaims.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Diagnostics;
using System.Net;
using System.Text;

namespace IssuerOfClaims.Services.Middleware
{
    public class ExceptionHandlerMiddleware : AbstractMiddleware
    {
        public ExceptionHandlerMiddleware(RequestDelegate requestDelegate) : base(requestDelegate)
        {
        }

        public override async Task Invoke(HttpContext context)
        {
            try
            {
                await _next(context);
            }
            catch (CustomException ex)
            {
                await SendProblemDetailsAsResponse(context, ex.Message, ex.StatusError);
            }
            catch (Exception ex)
            {
                await SendProblemDetailsAsResponse(context, ex.Message);
            }
            finally
            {
                // TOOD: log exception, will be done in future
            }
        }

        private static async Task SendProblemDetailsAsResponse(HttpContext context, string message, HttpStatusCode statusCode = HttpStatusCode.InternalServerError)
        {
            ProblemDetails details = AddProblemDetailInformation(message, statusCode);

            context.Response.StatusCode = (int)statusCode;
            await context.Response.WriteAsJsonAsync(details);
        }

        private static ProblemDetails AddProblemDetailInformation(string message, HttpStatusCode statusCode = HttpStatusCode.InternalServerError)
        {
            ProblemDetails details = new ProblemDetails();

            details.Status = (int)statusCode;
            details.Detail = message;
            details.Type = nameof(statusCode);

            return details;
        }
    }
}
