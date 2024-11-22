using IssuerOfClaims.Extensions;
using ServerUltilities;
using ServerUltilities.Extensions;

namespace IssuerOfClaims.Services.Middleware
{
    public abstract class AbstractMiddleware
    {
        internal readonly RequestDelegate _next;

        public AbstractMiddleware(RequestDelegate @delegate)
        {
            _next = @delegate;
        }

        public virtual async Task Invoke(HttpContext context)
        {
            throw new CustomException(ExceptionMessage.NOT_IMPLEMENTED);
        }
    }
}
