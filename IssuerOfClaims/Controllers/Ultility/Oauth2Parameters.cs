using IssuerOfClaims.Extensions;
using Microsoft.IdentityModel.Tokens;
using ServerUltilities.Extensions;
using ServerUltilities.Identity;
using static ServerUltilities.Identity.OidcConstants;

namespace IssuerOfClaims.Controllers.Ultility
{
    /// <summary>
    /// Implement specs from https://openid.net/specs/openid-connect-core-1_0.html
    /// </summary>
    public class Oauth2Parameters: AbtractRequestParamters
    {
        #region requested parameters
        /// <summary>
        /// TODO: try to add nonce in flow, will check it late
        ///     : because "state" still RECOMMENDED in some case, so I will use it when it's provided for identity server
        /// </summary>
        public Parameter State { get; private set; } = new Parameter(AuthorizeRequest.State);

        /// <summary>
        /// TODO: base on scope, I will add claims in id token, so it will need to be verified with client's scope in memory or database
        ///    : Verify that a scope parameter is present and contains the openid scope value.
        ///    : (If no openid scope value is present, the request may still be a valid OAuth 2.0 request but is not an OpenID Connect request.)
        /// </summary>
        public Parameter Scope { get; private set; } = new Parameter(AuthorizeRequest.Scope);

        /// <summary>
        /// TODO: because in implicit grant flow, redirectUri is use to redirect to user-agent, 
        ///     : in logically, client does not know it before user-agent send a redirect_uri to client
        ///     : with browser's work, I think many browser can be user-agent, so it will be safe when client asks for redirect_uri from user-agent
        /// </summary>
        public Parameter RedirectUri { get; private set; } = new Parameter(AuthorizeRequest.RedirectUri);

        // TODO: need to compare with existing client in memory or database
        public Parameter ClientId { get; private set; } = new Parameter(AuthorizeRequest.ClientId);
        #endregion

        #region multiple response type encoding practices
        /// <summary>
        /// Informs the Authorization Server of the mechanism to be used for returning parameters from the Authorization Endpoint. 
        /// This use of this parameter is NOT RECOMMENDED when the Response Mode that would be requested is the default mode specified for the Response Type.
        /// </summary>
        public Parameter ResponseMode { get; private set; } = new Parameter(AuthorizeRequest.ResponseMode);
        /// <summary>
        /// from https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
        /// </summary>
        public Parameter ResponseType { get; private set; } = new Parameter(AuthorizeRequest.ResponseType);
        #endregion

        #region optional parameters
        /// <summary>
        /// TODO: from https://openid.net/specs/openid-connect-prompt-create-1_0.html
        ///     : When the prompt parameter is used in an authorization request to the authorization endpoint with the value of create,
        ///     : it indicates that the user has chosen to be shown the account creation experience rather than the login experience
        /// </summary>
        public Parameter Prompt { get; private set; } = new Parameter(AuthorizeRequest.Prompt);
        /// <summary>
        /// TODO: try to add nonce in flow, will check it late
        ///     : because "nonce" still OPTIONAL in some case, so I will use it when it's provided for identity server
        /// </summary>
        public Parameter Nonce { get; private set; } = new Parameter(AuthorizeRequest.Nonce);
        /// <summary>
        /// from https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
        /// </summary>
        public Parameter MaxAge { get; private set; } = new Parameter(AuthorizeRequest.MaxAge);
        /// <summary>
        /// from https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
        /// </summary>
        public Parameter UiLocales { get; private set; } = new Parameter(AuthorizeRequest.UiLocales);
        /// <summary>
        /// from https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
        /// </summary>
        public Parameter IdTokenHint { get; private set; } = new Parameter(AuthorizeRequest.IdTokenHint);

        public Parameter CodeChallenge { get; private set; } = new Parameter(AuthorizeRequest.CodeChallenge);
        public Parameter CodeChallengeMethod { get; private set; } = new Parameter(AuthorizeRequest.CodeChallengeMethod);

        // TODO: will add display parameter
        // TODO: will add prompt parameter
        // TODO: will add arc_value parameters
        #endregion

        public Oauth2Parameters(string? queryString): base (queryString)
        {
            this.Scope.SetValue(System.Uri.UnescapeDataString(requestQuery.GetFromQueryString(AuthorizeRequest.Scope)));
            ValidateScope();

            this.Nonce.SetValue(requestQuery.GetFromQueryString(AuthorizeRequest.Nonce));
            this.Prompt.SetValue(requestQuery.GetFromQueryString(AuthorizeRequest.Prompt));
            this.State.SetValue(requestQuery.GetFromQueryString(AuthorizeRequest.State));
            this.ClientId.SetValue(requestQuery.GetFromQueryString(AuthorizeRequest.ClientId));
            this.RedirectUri.SetValue(System.Uri.UnescapeDataString(requestQuery.GetFromQueryString(AuthorizeRequest.RedirectUri)));

            this.CodeChallenge.SetValue(requestQuery.GetFromQueryString(AuthorizeRequest.CodeChallenge));
            this.CodeChallengeMethod.SetValue(requestQuery.GetFromQueryString(AuthorizeRequest.CodeChallengeMethod));
            ValidatePKCEParameters();

            this.ResponseType.SetValue(requestQuery.GetFromQueryString(AuthorizeRequest.ResponseType));
            ValidateResponseType();

            var responseMode = requestQuery.GetFromQueryString(AuthorizeRequest.ResponseMode);
            this.ResponseMode.SetValue(string.IsNullOrEmpty(responseMode) ? GetDefaultResponseModeByResponseType(this.ResponseType.Value) : responseMode);
        }

        private void ValidateScope()
        {
            if (!this.Scope.Value.Contains(StandardScopes.OpenId))
                throw new CustomException(501, ExceptionMessage.AUTHORIZE_SCOPES_MUST_HAVE_OPENID);
        }

        private void ValidatePKCEParameters()
        {
            if ((this.CodeChallengeMethod.HasValue && !this.CodeChallenge.HasValue)
                || (this.CodeChallenge.HasValue && !this.CodeChallengeMethod.HasValue))
                throw new CustomException(400, ExceptionMessage.CODECHALLENGE_CODECHALLENGEMETHODE_NOT_HAVE_VALUE_SIMUTANEOUSLY);
        }

        /// <summary>
        /// TODO: must be used after ResponseType has value
        /// </summary>
        /// <exception cref="InvalidDataException"></exception>
        private void ValidateResponseType()
        {
            if (!Constants.SupportedResponseTypes.Contains(this.ResponseType.Value))
                throw new CustomException(400, ExceptionMessage.RESPONSE_TYPE_NOT_SUPPORTED);
        }

        private string GetDefaultResponseModeByResponseType(string responseType)
        {
            string responseMode = "";

            // get grant type for response type
            string grantType = Constants.ResponseTypeToGrantTypeMapping[responseType];
            // map grant type with allowed response mode
            string[] responseModes = Constants.AllowedResponseModesForGrantType[grantType].ToArray();

            // TODO: by default
            if (responseType.Equals(ResponseTypes.Code))
                responseMode = responseModes.First(m => m.Equals(ResponseModes.Query));
            else if (responseType.Equals(ResponseTypes.Token))
                responseMode = responseModes.First(m => m.Equals(ResponseModes.Fragment));


            return responseMode;
        }
    }
}
