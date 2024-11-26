using IssuerOfClaims.Extensions;
using Microsoft.EntityFrameworkCore;
using IssuerOfClaims.Models.DbModel;
using ServerUltilities.Extensions;
using System.Net;

namespace IssuerOfClaims.Services.Database
{
    public class IdentityRequestHandlerDbServices : DbTableServicesBase<IdentityRequestHandler>, IIdentityRequestHandlerDbServices
    {
        //private readonly ILogger _logger;

        public IdentityRequestHandlerDbServices(ILoggerFactory logger)
        {
        }

        public async Task<IdentityRequestHandler> FindByAuthCodeAsync(string authorizationCode)
        {
            IdentityRequestHandler obj = null;
            await UsingDbSetAsync((_tokenRequestHandlers) =>
            {
                obj = _tokenRequestHandlers
                    .Include(l => l.User)
                    .Include(l => l.RequestSession)
                    .Where(l => l.RequestSession != null && l.RequestSession.AuthorizationCode != null && l.RequestSession.AuthorizationCode.Equals(authorizationCode))
                    .AsSplitQuery()
                    .AsNoTracking()
                    .First();
            });

            ValidateEntity(obj, HttpStatusCode.BadRequest, $"{nameof(IdentityRequestHandlerDbServices)}: {ExceptionMessage.OBJECT_IS_NULL}");
            //_logger.LogInformation($"current thread id is {Thread.CurrentThread.ManagedThreadId}");

            return obj;
        }

        // TODO:
        public async Task<IdentityRequestHandler> FindByIdAsync(Guid currentRequestHandlerId)
        {
            IdentityRequestHandler obj = null;
            await UsingDbSetAsync((_tokenRequestHandlers) =>
            {
                obj = _tokenRequestHandlers
                .Include(t => t.User)
                .Include(t => t.Client)
                .Include(t => t.RequestSession)
                .Include(t => t.TokensPerRequestHandlers).ThenInclude(t => t.TokenResponse)
                .Where(t => t.Id.Equals(currentRequestHandlerId))
                .AsSplitQuery()
                .AsNoTracking()
                .First();
            });

            ValidateEntity(obj, HttpStatusCode.NotFound, $"{nameof(IdentityRequestHandlerDbServices)}: {ExceptionMessage.OBJECT_IS_NULL}");

            return obj;
        }

        public IdentityRequestHandler GetDraftObject()
        {
            return new IdentityRequestHandler();
        }

        // TODO:
        // Create new session's object whenever a request involve with identity services is called
        // - set for it authorization code when authorization code flow is initiated, add code challenger, add id token, access token expired time and access token when a request for access token include grant_type is called
        // - set for it id token and access token when implicit grant (with form_post or not) is initiated
        // =>  after everything is done following a particular flow which is used for authentication, save this session object to database
        // - TODO: these following few lines is good ideal, I think, but I have problems when trying to implement it, so for now, I save everything in db
        // * Note: I don't want to save it when initiate authentication process and get it from database when it's call,
        //       : because, a particular session is used along with authentication process will be among latest, and search for it in db can create performance cost when this server is used long enough.
        //       : instead of search from db, save 100 session in used, and get it from memory (from authorization code, or id_token) is easier than query 100 object from 100.000 object table...
    }

    public interface IIdentityRequestHandlerDbServices : IDbContextBase<IdentityRequestHandler>
    {
        Task<IdentityRequestHandler> FindByAuthCodeAsync(string authorizationCode);
        Task<IdentityRequestHandler> FindByIdAsync(Guid currentRequestHandlerId);
        IdentityRequestHandler GetDraftObject();
    }
}
