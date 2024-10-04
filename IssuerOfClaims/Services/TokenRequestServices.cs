using IssuerOfClaims.Database;
using IssuerOfClaims.Services.Database;
using Microsoft.EntityFrameworkCore;
using ServerDbModels;

namespace IssuerOfClaims.Services
{
    public class TokenRequestServices : ITokenRequestServices
    {
        private ITokenRequestHandlerDbServices _requestHandlerServices;
        //private ITokenResponseDbServices _responseServices;
        //private ITokenRequestSessionDbServices _requestSessionServices;
        private ILogger _logger;

        public TokenRequestServices(ITokenRequestHandlerDbServices requestHandlerServices, ILoggerFactory logger)
            //ITokenResponseDbServices responseServices, ITokenRequestSessionDbServices requestSessionServices,
        {
            //_configuration = configuration;
            //var dbContext = CreateDbContext(configuration);

            _requestHandlerServices = requestHandlerServices;
            //_responseServices = responseServices;
            //_requestSessionServices = requestSessionServices;

            _logger = logger.CreateLogger("TokenRequestServices");
        }

        public TokenRequestHandler CreateTokenRequestSession(UserIdentity user, Client client)
        {
            var newObj = new TokenRequestHandler()
            {
                //User = user,
                TokenRequestSession = new TokenRequestSession()
                {
                    //Client = client
                }
            };

            try
            {
                //if (_requestHandlerServices.IsValueCreated)
                _requestHandlerServices.Create(newObj);
            }
            catch (Exception)
            {

                throw;
            }


            return newObj;
        }

        //public TokenRequestHandler FindByAuthorizationCode(string authorizationCode)
        //{
        //    var obj = _requestHandlerServices.FindLoginSessionWithAuthorizationCodeAsync(authorizationCode);

        //    return obj;
        //}

        public bool WhenLoginComplete(TokenRequestHandler session)
        {
            try
            {
                session.TokenRequestSession.IsInLoginSession = false;
                _requestHandlerServices.Update(session);

                //_loginSession.Remove(session);
            }
            catch (Exception)
            {
                return false;
            }
            return true;
        }

        public bool UpdateTokenRequestSession(TokenRequestHandler session)
        {
            //if (session.TokenResponse != null)
            //{
            //    _responseServices.Update(session.TokenResponse);
            //}
            //if (session.TokenRequestSession != null)
            //{
            //    _requestSessionServices.Update(session.TokenRequestSession);
            //}
            //_logger.LogInformation(1, $"FindByAccessToken current thread is {Thread.CurrentThread.ManagedThreadId}");

            return _requestHandlerServices.Update(session);
        }

        //public TokenResponse CreateTokenResponse(TokenRequestHandler session)
        //{
        //    var obj = new TokenResponse()
        //    {
        //        TokenRequestHandler = session,
        //    };

        //    _responseServices.Create(obj);
        //    //_loginServices.SaveChanges();

        //    return obj;
        //}

        //public bool UpdateInsideTokenResponse(TokenRequestHandler session)
        //{
        //    if (session.TokenResponse != null)
        //    {
        //        _responseServices.Update(session.TokenResponse);
        //        return true;
        //    }
        //    return false;
        //}

        //public TokenRequestHandler FindByAccessToken(string accessToken)
        //{
        //    var session = _requestHandlerServices.FindByAccessToken(accessToken);

        //    return session;
        //}

        //public TokenRequestHandler FindByRefreshToken(string refreshToken)
        //{
        //    var session = _requestHandlerServices.FindByRefreshToken(refreshToken);

        //    return session;
        //}


        private DbContextManager CreateDbContext(IConfigurationManager configuration)
        {
            var contextOptions = new DbContextOptionsBuilder<DbContextManager>()
                 .UseSqlServer(configuration.GetConnectionString(DbUltilities.DatabaseName))
                 .Options;

            var dbContext = new DbContextManager(contextOptions, null);
            return dbContext;
        }
    }

    public interface ITokenRequestServices
    {
        //TokenResponse CreateTokenResponse(TokenRequestHandler loginSession);
        TokenRequestHandler CreateTokenRequestSession(UserIdentity user, Client client);
        //TokenRequestHandler FindByAuthorizationCode(string authorizationCode);
        //TokenRequestHandler FindByAccessToken(string accessToken);
        //TokenRequestHandler FindByRefreshToken(string refreshToken);
        bool UpdateTokenRequestSession(TokenRequestHandler session);
        //bool UpdateInsideTokenResponse(TokenRequestHandler session);
        bool WhenLoginComplete(TokenRequestHandler session);
    }
}
