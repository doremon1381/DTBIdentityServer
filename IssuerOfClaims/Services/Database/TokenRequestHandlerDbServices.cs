using IssuerOfClaims.Database;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using ServerDbModels;

namespace IssuerOfClaims.Services.Database
{
    public class TokenRequestHandlerDbServices : DbTableBase<TokenRequestHandler>, ITokenRequestHandlerDbServices
    {
        //private DbSet<TokenRequestHandler> _tokenRequestHandlers;
        //private readonly ILogger _logger;

        public TokenRequestHandlerDbServices(ILoggerFactory logger)
            //: base(configuration)
        {
            //_logger = logger.CreateLogger("TokenRequestHandlerServices");
        }

        public TokenRequestHandler FindByAuthorizationCode(string authorizationCode)
        {
            TokenRequestHandler obj = null;
            UsingDbSet((_tokenRequestHandlers) =>
            {
                var obj1 = _tokenRequestHandlers
                    .Include(l => l.User)
                    .Include(l => l.TokenResponsePerHandlers).ThenInclude(t => t.TokenResponse)
                    .Include(l => l.TokenRequestSession).ThenInclude(t => t.Client).ToList();
                obj = obj1.First(l => l.TokenRequestSession != null && l.TokenRequestSession.AuthorizationCode != null && l.TokenRequestSession.AuthorizationCode.Equals(authorizationCode));
            });

            ValidateEntity(obj);
            //_logger.LogInformation($"current thread id is {Thread.CurrentThread.ManagedThreadId}");

            return obj;
        }

        public TokenRequestHandler FindById(int currentRequestHandlerId)
        {
            TokenRequestHandler obj = null;
            UsingDbSet((_tokenRequestHandlers) =>
            {
                obj = _tokenRequestHandlers
                .Include(t => t.User)
                .Include(t => t.TokenRequestSession).ThenInclude(t => t.Client)
                .Include(t => t.TokenResponsePerHandlers).ThenInclude(t => t.TokenResponse)
                .First(t => t.Id.Equals(currentRequestHandlerId));
            });

            ValidateEntity(obj);

            return obj;
        }

        public TokenRequestHandler GetDraftObject()
        {
            return new TokenRequestHandler();
        }

        //public TokenRequestHandler FindByRefreshToken(string refreshToken)
        //{
        //    throw new NotImplementedException();
        //}


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

    public interface ITokenRequestHandlerDbServices : IDbContextBase<TokenRequestHandler>
    {
        TokenRequestHandler FindByAuthorizationCode(string authorizationCode);
        TokenRequestHandler FindById(int currentRequestHandlerId);
        TokenRequestHandler GetDraftObject();
    }
}
