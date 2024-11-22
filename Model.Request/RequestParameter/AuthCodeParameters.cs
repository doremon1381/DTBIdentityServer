namespace IssuerOfClaims.Models.Request.RequestParameter
{
    /// <summary>
    /// Implement specs from https://openid.net/specs/openid-connect-core-1_0.html
    /// </summary>
    public class AuthCodeParameters : IRequestParameters
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
        /// <summary>
        /// TODO: not in OpenID specs, currently used for redirecting from login web to server
        /// </summary>
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

        public AuthCodeParameters()
        {

        }
    }

    //public interface IAuthCodeParameters: IRequestParameters
    //{
    //    Parameter State { get;  set; }
    //    Parameter Scope { get; set; }
    //    Parameter RedirectUri { get; set; }
    //    Parameter ClientId { get; set; }
    //    Parameter ResponseType { get; set; }
    //    Parameter ResponseMode { get; set; }
    //    Parameter Prompt { get; set; }
    //    Parameter ConsentGranted { get; set; }
    //    Parameter Nonce { get; set; }
    //    Parameter MaxAge { get; set; }
    //    Parameter UiLocales { get; set; }
    //    Parameter IdTokenHint { get; set; }
    //    Parameter CodeChallenge { get; set; }
    //    Parameter CodeChallengeMethod { get; set; }

    //}
}
