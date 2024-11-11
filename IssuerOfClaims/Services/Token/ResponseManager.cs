﻿using IssuerOfClaims.Services.Database;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using ServerDbModels;
using ServerUltilities;
using ServerUltilities.Identity;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using IssuerOfClaims.Extensions;
using System.Text;
using System.Net;
using IssuerOfClaims.Models;
using IssuerOfClaims.Models.Request;
using Google.Apis.Auth;

namespace IssuerOfClaims.Services.Token
{
    /// <summary>
    /// Issue id token, refresh token and access token
    /// </summary>
    public class ResponseManager : IResponseManager
    {
        private readonly IIdentityRequestHandlerServices _requestHandlerServices;
        private readonly GoogleClientConfiguration _googleClientConfiguration;

        public ResponseManager(IIdentityRequestHandlerServices requestHandlerServices, GoogleClientConfiguration googleClientSettings)
        {
            _requestHandlerServices = requestHandlerServices;

            _googleClientConfiguration = googleClientSettings;
        }

        #region issue access token for token request with refresh token
        // TODO: will check again
        public async Task<string> IssueTokenByRefreshToken(string incomingRefreshToken)
        {
            var refreshToken = await _requestHandlerServices.FindRefreshTokenAsync(incomingRefreshToken);
            IsRefreshTokenAlive(refreshToken.TokenExpiried);

            string responseBody = "";
            if (!string.IsNullOrEmpty(refreshToken.ExternalSource))
            {
                // TODO: will update this part later
                responseBody = await RefreshAccessTokenFromExternalSourceAsync(refreshToken.Token, refreshToken.ExternalSource);
            }
            else
            {
                var lastestRefreshTokenBeUsed = refreshToken.TokensPerIdentityRequests.Last();
                var tokenRequestHandler = await _requestHandlerServices.FindByIdAsync(lastestRefreshTokenBeUsed.IdentityRequestHandlerId);

                // create new id token, remove the old, add the new into previous authenticate session
                // create new access token if it's expired, if access token is created new, remove the old, add the new one into previous authenticate session
                // create new refresh token if it's expired, if refresh token is created new, remove the old, add the new one into previous authenticate session

                var accessToken = RefreshAccessToken_IssuseToken(tokenRequestHandler, tokenRequestHandler.TokensPerRequestHandlers.First(t => t.TokenResponse.TokenType.Equals(OidcConstants.TokenTypes.AccessToken)));

                var idToken = await _requestHandlerServices.GenerateIdTokenAsync(tokenRequestHandler.User, tokenRequestHandler.RequestSession.Scope, ""
                    , tokenRequestHandler.Client.ClientId, tokenRequestHandler.SuccessAt.Value.ToString());

                responseBody = await ResponseUtilities.CreateTokenResponseStringAsync(accessToken.Token, idToken, accessToken.TokenExpiried);
            }

            return responseBody;
        }

        private static bool IsRefreshTokenAlive(DateTime expiredTime)
        {
            if (expiredTime <= DateTime.Now)
                throw new CustomException(ExceptionMessage.REFRESH_TOKEN_EXPIRED, HttpStatusCode.Unauthorized);

            return true;
        }

        private TokenResponse RefreshAccessToken_IssuseToken(IdentityRequestHandler tokenRequestHandler, TokenForRequestHandler tokenResponsePerIdentityRequest)
        {
            TokenResponse token = tokenResponsePerIdentityRequest.TokenResponse;

            if (token.TokenExpiried < DateTime.Now)
            {
                token = _requestHandlerServices.CreateToken(OidcConstants.TokenTypes.AccessToken);

                _requestHandlerServices.DeleteTokenResponse(tokenResponsePerIdentityRequest);
                _requestHandlerServices.CreateTokenResponsePerIdentityRequest(tokenRequestHandler, token);
            }

            return token;
        }
        #endregion

        #region issue token for authorization request
        public async Task<string> ACF_II_CreateResponseAsync(Guid userId, Guid idOfClient, string clientId, Guid currentRequestHandlerId)
        {
            var currentRequestHandler = await _requestHandlerServices.FindByIdAsync(currentRequestHandlerId);

            // TODO: use this temporary
            //TokenResponse idToken = await ACF_CreateIdToken(currentRequestHandler, clientId);
            string idToken = await _requestHandlerServices.GenerateIdTokenAsync(currentRequestHandler.User, currentRequestHandler.RequestSession.Scope, currentRequestHandler.RequestSession.Nonce, clientId, clientId);

            // I want to reuse token response if it is not expired
            var latestRefreshToken = await _requestHandlerServices.FindLastTokensPerIdentityRequestAsync(userId, idOfClient, needAccessToken: false);
            var latestAccessToken = await _requestHandlerServices.FindLastTokensPerIdentityRequestAsync(userId, idOfClient, needAccessToken: true);

            TokenResponse refreshToken = null;
            TokenResponse accessToken = null;

            // TODO: at this step, need to check offline_access is inside authrization login request is true or fault
            //     : if fault, then response will not include refresh token
            //     : if true, then add refresh token along with response
            if (currentRequestHandler.RequestSession.IsOfflineAccess)
            {
                // latest token response does not have refresh token
                if (latestRefreshToken == null
                    || latestRefreshToken.TokenResponse == null)
                {
                    refreshToken = _requestHandlerServices.CreateToken(OidcConstants.TokenTypes.RefreshToken);

                    // latest access token can be used
                    // , by logic of creation token response, those two (access-refresh token) will go along as a pair
                    if (latestAccessToken != null && latestAccessToken.TokenResponse.TokenExpiried > DateTime.Now)
                    {
                        accessToken = latestAccessToken.TokenResponse;
                    }
                    // latest access token can not be re-used, expired
                    else
                    {
                        // if expired, create new
                        accessToken = _requestHandlerServices.CreateToken(OidcConstants.TokenTypes.AccessToken);
                    }
                }
                // latest token response has refresh token
                else if (latestRefreshToken != null && latestRefreshToken.TokenResponse != null)
                {
                    // access token and refresh token can be re-used 
                    if (latestAccessToken.TokenResponse.TokenExpiried > DateTime.Now
                        && latestRefreshToken.TokenResponse.TokenExpiried > DateTime.Now)
                    {
                        accessToken = latestAccessToken.TokenResponse;
                        refreshToken = latestRefreshToken.TokenResponse;
                    }
                    // refresh token can be re-used, but not access token
                    else if (latestAccessToken.TokenResponse.TokenExpiried <= DateTime.Now
                            && latestRefreshToken.TokenResponse.TokenExpiried > DateTime.Now)
                    {
                        // access token expired time may over the refresh token expired time
                        TimeSpan diff = (TimeSpan)(latestRefreshToken.TokenResponse.TokenExpiried - DateTime.Now);
                        var expiredTime = diff.TotalSeconds < 3600 ? DateTime.Now.AddSeconds(diff.TotalSeconds)
                            : DateTime.Now.AddHours(1);

                        accessToken = _requestHandlerServices.CreateToken(OidcConstants.TokenTypes.AccessToken, expiredTime);
                        refreshToken = latestRefreshToken.TokenResponse;
                    }
                    // neither access token and refresh token cant be re-used
                    else if (latestAccessToken.TokenResponse.TokenExpiried <= DateTime.Now
                        && latestRefreshToken.TokenResponse.TokenExpiried <= DateTime.Now)
                    {
                        accessToken = _requestHandlerServices.CreateToken(OidcConstants.TokenTypes.AccessToken);
                        refreshToken = _requestHandlerServices.CreateToken(OidcConstants.TokenTypes.RefreshToken);
                    }
                    #region for test
                    //else if (latestAccessToken.TokenResponse.TokenExpiried > DateTime.Now
                    //    && latestRefreshToken.TokenResponse.TokenExpiried < DateTime.Now)
                    //{
                    //    //var tokenResponse = _tokenResponseDbServices.CreateAccessToken();
                    //    //currentRequestHandler.TokenResponse = tokenResponse;

                    //    //string access_token = RNGCryptoServicesUltilities.RandomStringGeneratingWithLength(64);
                    //    //string refresh_token = RNGCryptoServicesUltilities.RandomStringGeneratingWithLength(64);

                    //    //tokenResponse.AccessToken = access_token;
                    //    //tokenResponse.IdToken = id_token;
                    //    //tokenResponse.AccessTokenExpiried = DateTime.Now.AddHours(1);
                    //    //tokenResponse.RefreshToken = refresh_token;
                    //    //tokenResponse.RefreshTokenExpiried = DateTime.Now.AddHours(4);

                    //    //responseBody = CreateTokenResponseBody(access_token, id_token, 3600, refresh_token);
                    //}
                    #endregion
                }
            }
            else if (!currentRequestHandler.RequestSession.IsOfflineAccess)
            {
                // latest access token can be used
                if (latestAccessToken != null && latestAccessToken.TokenResponse.TokenExpiried > DateTime.Now)
                    accessToken = latestAccessToken.TokenResponse;
                else
                {
                    // create new 
                    accessToken = _requestHandlerServices.CreateToken(OidcConstants.TokenTypes.AccessToken);
                }
            }

#pragma warning disable CS8602 // Dereference of a possibly null reference.
            // TODO: at this step, if accessToken is null, then something is wrong!
            var responseBody = await ResponseUtilities.CreateTokenResponseStringAsync(accessToken.Token, idToken, accessToken.TokenExpiried, refreshToken == null ? "" : refreshToken.Token);
#pragma warning restore CS8602 // Dereference of a possibly null reference.

            await _requestHandlerServices.ACF_II_BackgroundStuff(currentRequestHandler, refreshToken, accessToken);

            return responseBody;
        }
        #endregion

        #region AuthGoogle, handle Google authentication
        public async Task<string> AuthGoogle_CreateResponseAsync(SignInGoogleParameters parameters, Client client,
            GoogleResponse googleResponse,
            GoogleJsonWebSignature.Payload payload, UserIdentity user)
        {
            var response = await ResponseUtilities.CreateTokenResponseStringAsync(googleResponse.AccessToken, googleResponse.IdToken,
                Utilities.Google_TimeSecondsToDateTime(payload.ExpirationTimeSeconds.Value),
                ExternalSources.Google,
                string.IsNullOrEmpty(googleResponse.RefreshToken) ? "" : googleResponse.RefreshToken);

            await _requestHandlerServices.AuthGoogle_BackgroundStuff(parameters.CodeVerifier.Value, googleResponse, payload, client, user);

            return response;
        }
        #endregion

        #region refresh access token from exeternal source
        private async Task<string> RefreshAccessTokenFromExternalSourceAsync(string refreshToken, string externalSource)
        {
            ValidateRefreshToken(refreshToken);
            // send request to google to refresh access token 
            var token = externalSource switch
            {
                ExternalSources.Google => await Google_RefershAccessToken(refreshToken),
                _ => throw new CustomException("Other external source is not implemented!", HttpStatusCode.NotImplemented)
            };
            return token;
        }

        private static bool ValidateRefreshToken(string refreshToken)
        {
            if (string.IsNullOrEmpty(refreshToken))
                throw new CustomException(ExceptionMessage.REFRESH_TOKEN_NULL, HttpStatusCode.NotAcceptable);

            return true;
        }

        private async Task<string> Google_RefershAccessToken(string refreshToken)
        {
            var content = string.Format("client_id={0}&client_secret={1}&refresh_token={2}&grant_type=refresh_token"
                , _googleClientConfiguration.ClientId
                , _googleClientConfiguration.ClientSecret
                , refreshToken);

            HttpWebRequest refreshRequest = (HttpWebRequest)WebRequest.Create(_googleClientConfiguration.TokenUri);
            refreshRequest.Method = "POST";
            refreshRequest.ContentType = "application/x-www-form-urlencoded";
            refreshRequest.Accept = "Accept=text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
            byte[] bytes = Encoding.ASCII.GetBytes(content);
            refreshRequest.ContentLength = bytes.Length;
            var stream = refreshRequest.GetRequestStream();
            await stream.WriteAsync(bytes, 0, bytes.Length);
            stream.Close();

            string responseText = "";

            WebResponse response = await refreshRequest.GetResponseAsync();
            using (StreamReader reader = new StreamReader(response.GetResponseStream()))
            {
                responseText = await reader.ReadToEndAsync();
            }

            return responseText;
        }
        #endregion

        #region issuse token for implicit grant's response
        public async Task<string> IGF_GetResponseAsync(UserIdentity user, AuthCodeParameters parameters, Client client)
        {
            var accessToken = await TaskUtilities.RunAttachedToParentTask(() => _requestHandlerServices.CreateToken(OidcConstants.TokenTypes.AccessToken));

            // TODO: scope is used for getting claims to send to client,
            //     : for example, if scope is missing email, then in id_token which will be sent to client will not contain email's information 
            var idToken = await _requestHandlerServices.GenerateIdTokenAsync(user, parameters.Scope.Value, parameters.Nonce.Value, client.ClientId);

            int secondsForTokenExpired = 3600;
            // Check response mode to know what kind of response is going to be used
            // return a form_post, url fragment or body of response
            string response = await ResponseUtilities.IGF_CreateResponse(parameters, idToken, accessToken.Token, secondsForTokenExpired);

            await _requestHandlerServices.IGF_BackgroundStuff(user, client, accessToken);

            return response;
        }
        #endregion

        #region create request handler for authorization code 
        public async Task<string> ACF_I_CreateResponseAsync(AuthCodeParameters @params, UserIdentity user, Client client, string authorizationCode)
        {
            var response = await ACF_I_CreateResponseBody(@params, authorizationCode);
            await _requestHandlerServices.ACF_I_BackgroundStuff(@params, user, client, authorizationCode);

            return response;
        }

        private static async Task<string> ACF_I_CreateResponseBody(AuthCodeParameters @params, string authorizationCode)
        {
            return await TaskUtilities.RunAttachedToParentTask(() => ResponseUtilities.ACF_I_CreateRedirectContent("", @params.ResponseMode.Value, @params.State.Value, authorizationCode, @params.Scope.Value, @params.Prompt.Value));
        }

        #endregion
    }

    public interface IResponseManager
    {
        Task<string> ACF_II_CreateResponseAsync(Guid userId, Guid idOfClient, string clientId, Guid currentRequestHandlerId);
        Task<string> ACF_I_CreateResponseAsync(AuthCodeParameters @params, UserIdentity user, Client client, string authorizationCode);
        Task<string> IGF_GetResponseAsync(UserIdentity user, AuthCodeParameters parameters, Client client);
        Task<string> IssueTokenByRefreshToken(string incomingRefreshToken);
        Task<string> AuthGoogle_CreateResponseAsync(SignInGoogleParameters parameters, Client client,
            GoogleResponse fromGoogle,
            GoogleJsonWebSignature.Payload payload, UserIdentity user);
    }
}