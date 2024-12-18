﻿using Google.Apis.Auth;
using IssuerOfClaims.Extensions;
using IssuerOfClaims.Models;
using IssuerOfClaims.Models.DbModel;
using IssuerOfClaims.Models.Request;
using IssuerOfClaims.Models.Request.RequestParameter;
using IssuerOfClaims.Services.Database;
using ServerUltilities;
using ServerUltilities.Identity;

namespace IssuerOfClaims.Services.Token
{
    public class RequestHanderService : IIdentityRequestHandlerService
    {
        private readonly IIdentityRequestSessionDbService _requestSessionDbServices;
        private readonly IIdentityRequestHandlerDbService _requestHandlerDbServices;
        private readonly ITokenForRequestHandlerDbService _tokensForIdentityRequestDbServices;
        private readonly ITokenService _tokenServices;

        public RequestHanderService(IIdentityRequestSessionDbService sessionDbServices, IIdentityRequestHandlerDbService requestHandlerDbServices
            , ITokenForRequestHandlerDbService tokensForIdentityRequestDbServices
            , ITokenService tokenServices)
        {
            _requestSessionDbServices = sessionDbServices;
            _requestHandlerDbServices = requestHandlerDbServices;
            _tokensForIdentityRequestDbServices = tokensForIdentityRequestDbServices;
            _tokenServices = tokenServices;
        }

        public IdentityRequestSession CreateRequestSession(Guid requestHandlerId)
        {
            return _requestSessionDbServices.CreateTokenRequestSession(requestHandlerId);
        }

        public IdentityRequestHandler GetDraftRequestHandler()
        {
            return _requestHandlerDbServices.GetDraftObject();
        }

        public bool UpdateRequestSession(IdentityRequestSession tokenRequestSession)
        {
            return _requestSessionDbServices.Update(tokenRequestSession);
        }

        public async Task<IdentityRequestHandler> FindByAuthCodeAsync(string authCode)
        {
            return await _requestHandlerDbServices.FindByAuthCodeAsync(authCode);
        }

        private IdentityRequestSession GetDraftRequestSession()
        {
            return _requestSessionDbServices.GetDraft();
        }

        public async Task<IdentityRequestHandler> FindByIdAsync(Guid id)
        {
            return await _requestHandlerDbServices.FindByIdAsync(id);
        }

        public bool CreateTokenResponsePerIdentityRequest(IdentityRequestHandler currentRequestHandler, TokenResponse tokenResponse)
        {
            TokenForRequestHandler tokensPerIdentityRequest = _tokensForIdentityRequestDbServices.GetDraftObject();
            tokensPerIdentityRequest.TokenResponse = tokenResponse;
            tokensPerIdentityRequest.IdentityRequestHandlerId = currentRequestHandler.Id;

            return _tokensForIdentityRequestDbServices.Update(tokensPerIdentityRequest);
        }

        private void SetRequestHandleToSuccess(IdentityRequestHandler requestHandler)
        {
            requestHandler.SuccessAt = DateTime.UtcNow;
            UpdateRequestHandler(requestHandler);
        }

        public bool UpdateRequestHandler(IdentityRequestHandler tokenRequestHandler)
        {
            return _requestHandlerDbServices.Update(tokenRequestHandler);
        }

        public bool DeleteTokenResponse(TokenForRequestHandler tokenForRequestHandler)
        {
            return _tokenServices.Delete(tokenForRequestHandler.TokenResponse) == true &&
                _tokensForIdentityRequestDbServices.Delete(tokenForRequestHandler) == true;
        }

        public async Task<TokenForRequestHandler> FindLastTokensPerIdentityRequestAsync(Guid userId, Guid idOfClient, bool isAccessToken)
        {
            return await _tokensForIdentityRequestDbServices.FindLastAsync(userId, idOfClient, isAccessToken);
        }

        #region token
        public async Task<TokenResponse> FindRefreshTokenAsync(string incomingRefreshToken)
        {
            return await _tokenServices.FindRefreshTokenAsync(incomingRefreshToken);
        }
        public async Task<string> GenerateIdTokenAsync(UserIdentity user, string scope, string? nonce, string clientId, string successAt = "")
        {
            return await _tokenServices.GenerateIdTokenAsync(user, scope, nonce, clientId, successAt);
        }
        public TokenResponse CreateToken(string accessToken)
        {
            return _tokenServices.CreateToken(accessToken);
        }
        public TokenResponse CreateToken(string accessToken, DateTime expiredTime)
        {
            return _tokenServices.CreateToken(accessToken, expiredTime);
        }
        #endregion

        #region for Google authorization
        public async Task AuthGoogle_BackgroundStuffAsync(string codeVerifier, GoogleResponse googleResponse, GoogleJsonWebSignature.Payload payload, Client client, UserIdentity user)
        {
            await TaskUtilities.RunAttachedToParentTask(() =>
            {
                // TODO: associate google info with current user identity inside database, using email to do it
                //     : priority information inside database, import missing info from google
                var requestHandler = AuthGoogle_ImportRequestHandlerData(codeVerifier, googleResponse.RefreshToken, client, user);

                // at this step, token request session is used for storing data
                SaveTokenFromExternalSource(googleResponse.AccessToken, googleResponse.RefreshToken
                    // TODO: comment for now
                    //, googleResponse.IdToken, payload.IssuedAtTimeSeconds.Value, payload.ExpirationTimeSeconds.Value
                    , googleResponse.AccessTokenIssueAt,
                    googleResponse.AccessTokenIssueAt.AddSeconds(googleResponse.ExpiredIn),
                        requestHandler, ExternalSources.Google);

                SetRequestHandleToSuccess(requestHandler);
            });
        }

        private IdentityRequestHandler AuthGoogle_ImportRequestHandlerData(string codeVerifier, string refreshToken, Client client, UserIdentity user)
        {
            var requestHandler = GetDraftRequestHandler();
            requestHandler.User = user;
            requestHandler.Client = client;

            UpdateRequestHandler(requestHandler);

            GoogleAuth_CreateRequestSession(codeVerifier, refreshToken, requestHandler);

            return requestHandler;
        }

        private void GoogleAuth_CreateRequestSession(string codeVerifier, string refreshToken, IdentityRequestHandler requestHandler)
        {
            var session = CreateRequestSession(requestHandler.Id);
            session.PKCE.CodeVerifier = codeVerifier;
            session.IsOfflineAccess = string.IsNullOrEmpty(refreshToken) ? false : true;

            UpdateRequestSession(session);
        }

        public bool SaveTokenFromExternalSource(string accessToken, string refreshToken
            // TODO: comment for now
            //, string idToken, long idToken_issuedAtTimeSeconds, long idToken_expirationTimeSeconds
            , DateTime accessTokenIssueAt, DateTime accessTokenExpiredIn
            , IdentityRequestHandler requestHandler, string externalSource)
        {
            var _accessToken = SaveExternalSourceToken(accessToken, accessTokenIssueAt, accessTokenExpiredIn, externalSource, OidcConstants.TokenTypes.AccessToken);
            CreateTokenResponsePerIdentityRequest(requestHandler, _accessToken);

            if (refreshToken != null)
            {
                var _refreshToken = SaveExternalSourceToken(accessToken, null, null, externalSource, OidcConstants.TokenTypes.RefreshToken);
                CreateTokenResponsePerIdentityRequest(requestHandler, _refreshToken);
            }

            // TODO: will think about how to handle idtoken, create one for user, update when information of user is changed or sth else
            //var _idToken = SaveExternalSourceToken(idToken, Utilities.Google_TimeSecondsToDateTime(idToken_issuedAtTimeSeconds), Utilities.Google_TimeSecondsToDateTime(idToken_expirationTimeSeconds), externalSource, OidcConstants.TokenTypes.IdentityToken);
            //CreateTokenResponsePerIdentityRequest(requestHandler, _idToken);

            return true;
        }

        private TokenResponse SaveExternalSourceToken(string tokenValue, DateTime? issueAt, DateTime? expiredTime, string externalSource, string tokenType)
        {
            var token = _tokenServices.CreateToken(tokenType, expiredTime, issueAt);
            token.Token = tokenValue;
            token.ExternalSource = externalSource;

            return token;
        }
        #endregion

        #region for implicit grant flow
        public async Task IGF_BackgroundStuffAsync(UserIdentity user, Client client, TokenResponse accessToken)
        {
            await TaskUtilities.RunAttachedToParentTask(() =>
            {
                // TODO: update must follow order, I will explain late
                var requestHandler = IGF_CreateTokenRequestHandlerWithSession(user, client, client.AllowedScopes);

                CreateTokenResponsePerIdentityRequest(requestHandler, accessToken);
                SetRequestHandleToSuccess(requestHandler);
            });
        }

        private IdentityRequestHandler IGF_CreateTokenRequestHandlerWithSession(UserIdentity user, Client client, string allowedScopes)
        {
            var requestSession = IGF_GetDraftRequestSession(allowedScopes);
            var requestHandler = GetDraftRequestHandler();
            requestHandler.User = user;
            requestHandler.Client = client;
            requestHandler.RequestSession = requestSession;

            UpdateRequestHandler(requestHandler);

            return requestHandler;
        }

        // TODO: will test again
        private IdentityRequestSession IGF_GetDraftRequestSession(string allowedScopes)
        {
            var tokenRequestSession = GetDraftRequestSession();

            tokenRequestSession.Scope = allowedScopes;
            tokenRequestSession.IsOfflineAccess = false;

            return tokenRequestSession;
        }
        #endregion

        #region for authorization code flow
        public async Task ACF_I_BackgroundStuffAsync(AuthCodeParameters @params, UserIdentity user, Client client, string authorizationCode)
        {
            await TaskUtilities.RunAttachedToParentTask(() =>
            {
                var acfProcessSession = GetDraftRequestSession();

                ACF_I_SaveSessionDetails(@params, acfProcessSession, authorizationCode);
                ACF_I_CreateIdentityRequestHandler(user, client, acfProcessSession);
            });
        }

        /// <summary>
        /// TODO: will fix some error when adding transient or scopped dbcontext
        /// </summary>
        /// <param name="user"></param>
        /// <param name="ACFProcessSession"></param>
        private void ACF_I_CreateIdentityRequestHandler(UserIdentity user, Client client, IdentityRequestSession draftRequestSession)
        {
            var requestHandler = GetDraftRequestHandler();
            requestHandler.User = user;
            // TODO: will check again
            requestHandler.Client = client;
            requestHandler.RequestSession = draftRequestSession;

            // TODO: will check again
            UpdateRequestHandler(requestHandler);
        }

        private void ACF_I_SaveSessionDetails(AuthCodeParameters parameters, IdentityRequestSession ACFProcessSession, string authorizationCode)
        {
            ACF_I_AddPKCEFromRequest(parameters.CodeChallenge.Value, parameters.CodeChallengeMethod.Value, parameters.CodeChallenge.HasValue, ACFProcessSession);
            ACF_I_AddOtherSessionData(parameters.Scope.Value, parameters.Nonce.Value, ACFProcessSession, parameters.RedirectUri.Value, authorizationCode);
        }

        private static void ACF_I_AddOtherSessionData(string scope, string nonce, IdentityRequestSession tokenRequestSession, string redirectUri, string authorizationCode)
        {
            tokenRequestSession.AuthorizationCode = authorizationCode;
            tokenRequestSession.Nonce = nonce;
            tokenRequestSession.RedirectUri = redirectUri;
            tokenRequestSession.Scope = scope;
            tokenRequestSession.IsOfflineAccess = scope.Contains(OidcConstants.StandardScopes.OfflineAccess);
        }

        private static void ACF_I_AddPKCEFromRequest(string codeChallenge, string codeChallengeMethod, bool codeChallenge_HasValue, IdentityRequestSession tokenRequestSession)
        {
            if (codeChallenge_HasValue)
            {
                tokenRequestSession.PKCE.CodeChallenge = codeChallenge;
                tokenRequestSession.PKCE.CodeChallengeMethod = codeChallengeMethod;
            }
        }

        public async Task ACF_II_BackgroundStuffAsync(IdentityRequestHandler requestHandler, TokenResponse? refreshToken, TokenResponse accessToken)
        {
            await TaskUtilities.RunAttachedToParentTask(() =>
            {
                CreateTokenResponsePerIdentityRequest(requestHandler, accessToken);
                // for example, offline_access = false
                if (refreshToken != null)
                    CreateTokenResponsePerIdentityRequest(requestHandler, refreshToken);
                // TODO: will think about how to handle idtoken, create one for user, update when information of user is changed or sth else
                //CreateTokenResponsePerIdentityRequest(currentRequestHandler, idToken);

                SetRequestHandleToSuccess(requestHandler);
            });
        }
        #endregion

        #region hybrid flow
        public async Task Hybrid_I_BackgroundStuff(AuthCodeParameters parameters, UserIdentity user, Client client, string authorizationCode, TokenResponse? accessToken)
        {
            await TaskUtilities.RunAttachedToParentTask(() =>
            {
                var acfProcessSession = GetDraftRequestSession();

                ACF_I_SaveSessionDetails(parameters, acfProcessSession, authorizationCode);
                ACF_I_CreateIdentityRequestHandler(user, client, acfProcessSession);

                // Add access token
                var requestHandler = _requestHandlerDbServices.FindByAuthCodeAsync(authorizationCode).GetAwaiter().GetResult();
                if (accessToken != null)
                {
                    CreateTokenResponsePerIdentityRequest(requestHandler, accessToken);
                    SetRequestHandleToSuccess(requestHandler);
                }
            });
        }
        #endregion

        #region client credentials
        public async Task CCF_BackgroundStuff(ClientCredentialsParameters parameters, TokenResponse accessToken, Client client)
        {
            await TaskUtilities.RunAttachedToParentTask(() =>
            {
                var ccfProcessSession = GetDraftRequestSession();

                CCF_SaveSessionData(ccfProcessSession, parameters.Scope.Value);
                CCF_CreateRequestHandler(client, ccfProcessSession, accessToken);
            });
        }

        private void CCF_CreateRequestHandler(Client client, IdentityRequestSession ccfProcessSession, TokenResponse accessToken)
        {
            var requestHandler = GetDraftRequestHandler();
            requestHandler.ClientId = client.Id;
            requestHandler.RequestSession = ccfProcessSession;

            UpdateRequestHandler(requestHandler);

            CreateTokenResponsePerIdentityRequest(requestHandler, accessToken);
        }

        private static void CCF_SaveSessionData(IdentityRequestSession ccfProcessSession, string scope)
        {
            ccfProcessSession.Scope = scope;
        }
        #endregion
    }

    public interface IIdentityRequestHandlerService
    {
        Task<IdentityRequestHandler> FindByAuthCodeAsync(string authCode);
        Task<TokenForRequestHandler> FindLastTokensPerIdentityRequestAsync(Guid userId, Guid idOfClient, bool isAccessToken);
        bool DeleteTokenResponse(TokenForRequestHandler tokenForRequestHandler);
        bool CreateTokenResponsePerIdentityRequest(IdentityRequestHandler currentRequestHandler, TokenResponse tokenResponse);
        Task<IdentityRequestHandler> FindByIdAsync(Guid id);
        Task AuthGoogle_BackgroundStuffAsync(string codeVerifier, GoogleResponse googleResponse, GoogleJsonWebSignature.Payload payload, Client client, UserIdentity user);
        Task ACF_I_BackgroundStuffAsync(AuthCodeParameters @params, UserIdentity user, Client client, string authorizationCode);
        Task ACF_II_BackgroundStuffAsync(IdentityRequestHandler currentRequestHandler, TokenResponse? refreshToken, TokenResponse accessToken);
        Task IGF_BackgroundStuffAsync(UserIdentity user, Client client, TokenResponse accessToken);
        #region token
        Task<TokenResponse> FindRefreshTokenAsync(string incomingRefreshToken);
        Task<string> GenerateIdTokenAsync(UserIdentity user, string scope, string? nonce, string clientId, string successAt = "");
        TokenResponse CreateToken(string tokenType);
        TokenResponse CreateToken(string tokenType, DateTime expiredTime);
        Task Hybrid_I_BackgroundStuff(AuthCodeParameters @params, UserIdentity user, Client client, string authorizationCode, TokenResponse? accessToken);
        Task CCF_BackgroundStuff(ClientCredentialsParameters parameters, TokenResponse accessToken, Client client);
        #endregion
    }
}
