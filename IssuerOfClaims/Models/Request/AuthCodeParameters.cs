using IssuerOfClaims.Extensions;
using IssuerOfClaims.Models;
using Microsoft.IdentityModel.Tokens;
using ServerUltilities.Extensions;
using ServerUltilities.Identity;
using System.Net;
using static ServerUltilities.Identity.OidcConstants;

namespace IssuerOfClaims.Models.Request
{
    /// <summary>
    /// Implement specs from https://openid.net/specs/openid-connect-core-1_0.html
    /// </summary>
    public class AuthCodeParameters : AbstractRequestParamters<AuthCodeParameters>
    {
        #region requested parameters
        /// <summary>
        /// TODO: try to add nonce in flow, will check it late
        ///     : because "state" still RECOMMENDED in some case, so I will use it when it's provided for identity server
        /// </summary>
        public Parameter State { get; private set; }

        /// <summary>
        /// TODO: base on scope, I will add claims in id token, so it will need to be verified with client's scope in memory or database
        ///    : Verify that a scope parameter is present and contains the openid scope value.
        ///    : (If no openid scope value is present, the request may still be a valid OAuth 2.0 request but is not an OpenID Connect request.)
        /// </summary>
        public Parameter Scope { get; private set; }

        /// <summary>
        /// TODO: because in implicit grant flow, redirectUri is use to redirect to user-agent, 
        ///     : in logically, client does not know it before user-agent send a redirect_uri to client
        ///     : with browser's work, I think many browser can be user-agent, so it will be safe when client asks for redirect_uri from user-agent
        /// </summary>
        public Parameter RedirectUri { get; private set; }

        // TODO: need to compare with existing client in memory or database
        public Parameter ClientId { get; private set; }
        #endregion

        #region multiple response type encoding practices
        /// <summary>
        /// <para> from https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest </para>
        /// <para> must be set before response mode</para>
        /// </summary>
        public Parameter ResponseType { get; private set; }
        /// <summary>
        /// Informs the Authorization Server of the mechanism to be used for returning parameters from the Authorization Endpoint. 
        /// This use of this parameter is NOT RECOMMENDED when the Response Mode that would be requested is the default mode specified for the Response Type.
        /// </summary>
        public Parameter ResponseMode { get; private set; }
        #endregion

        #region optional parameters
        /// <summary>
        /// TODO: from https://openid.net/specs/openid-connect-prompt-create-1_0.html
        /// <para> When the prompt parameter is used in an authorization request to the authorization endpoint with the value of create </para>
        /// <para> ,it indicates that the user has chosen to be shown the account creation experience rather than the login experience </para>
        ///     . For now, I don't handle prompt value, by default prompt=none
        /// </summary>
        public Parameter Prompt { get; private set; }
        public Parameter ConsentGranted { get; private set; }
        /// <summary>
        /// TODO: try to add nonce in flow, will check it late
        ///     : because "nonce" still OPTIONAL in some case, so I will use it when it's provided for identity server
        /// </summary>
        public Parameter Nonce { get; private set; }
        /// <summary>
        /// from https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
        /// </summary>
        public Parameter MaxAge { get; private set; }
        /// <summary>
        /// from https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
        /// </summary>
        public Parameter UiLocales { get; private set; }
        /// <summary>
        /// from https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
        /// </summary>
        public Parameter IdTokenHint { get; private set; }

        public Parameter CodeChallenge { get; private set; }
        public Parameter CodeChallengeMethod { get; private set; }

        // TODO: will add display parameter
        // TODO: will add prompt parameter
        // TODO: will add arc_value parameters
        #endregion

#pragma warning disable CS8618 // Non-nullable field must contain a non-null value when exiting constructor. Consider declaring as nullable.
        public AuthCodeParameters(string? queryString) : base(queryString)
#pragma warning restore CS8618 // Non-nullable field must contain a non-null value when exiting constructor. Consider declaring as nullable.
        {
            ValidateScope();
            ValidatePKCEParameters();
            ValidateResponseType();
            //ValidatePrompt();

            // TODO: will change later
            SetDefaultPrompt();
        }

        private void ValidatePrompt()
        {
            if (Prompt.HasValue)
            {
                if (!Constants.SupportedPromptModes.Contains(Prompt.Value))
                    throw new CustomException(ExceptionMessage.PROMPT_VALUE_NOT_VALID, HttpStatusCode.BadRequest);
                if (Constants.SupportConsentGrantedValue.Contains(ConsentGranted.Value))
                    throw new CustomException(ExceptionMessage.PROMPT_CONSENT_VALUE_NOT_VALID, HttpStatusCode.BadRequest);
            }
        }

        private void SetDefaultPrompt()
        {
            Prompt.SetValue(PromptModes.None);
        }

        private void ValidateScope()
        {
            if (!Scope.Value.Contains(StandardScopes.OpenId))
                throw new CustomException(ExceptionMessage.AUTHORIZE_SCOPES_MUST_HAVE_OPENID, HttpStatusCode.BadRequest);
        }

        private void ValidatePKCEParameters()
        {
            if (CodeChallengeMethod.HasValue && !CodeChallenge.HasValue
                || CodeChallenge.HasValue && !CodeChallengeMethod.HasValue)
                throw new CustomException(ExceptionMessage.CODECHALLENGE_CODECHALLENGEMETHOD_NOT_HAVE_VALUE_SIMUTANEOUSLY, HttpStatusCode.BadRequest);
        }

        /// <summary>
        /// TODO: must be used after ResponseType has value
        /// </summary>
        /// <exception cref="InvalidDataException"></exception>
        private void ValidateResponseType()
        {
            if (!Constants.SupportedResponseTypes.Contains(ResponseType.Value))
                throw new CustomException(ExceptionMessage.RESPONSE_TYPE_NOT_SUPPORTED, HttpStatusCode.BadRequest);
        }
    }
}
