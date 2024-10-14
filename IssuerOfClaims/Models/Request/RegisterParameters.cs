using IssuerOfClaims.Extensions;
using IssuerOfClaims.Models;
using ServerUltilities.Extensions;
using ServerUltilities.Identity;
using System.Web;
using static ServerUltilities.Identity.Constants;
using static ServerUltilities.Identity.OidcConstants;

namespace IssuerOfClaims.Models.Request
{
    public class RegisterParameters : AbstractRequestParamters<RegisterParameters>
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
        //public Parameter Scope { get; private set; } = new Parameter(AuthorizeRequest.Scope);

        // TODO: because in implicit grant flow, redirectUri is use to redirect to user-agent, 
        //     : in logically, client does not know it before user-agent send a redirect_uri to client
        //     : with browser's work, I think many browser can be user-agent, so it will be safe when client asks for redirect_uri from user-agent
        public Parameter RedirectUri { get; private set; }

        // TODO: need to compare with existing client in memory or database
        public Parameter ClientId { get; private set; }
        public Parameter UserName { get; private set; }
        public Parameter Password { get; private set; }
        #endregion

        #region optional parameters
        /// <summary>
        /// TODO: try to add nonce in flow, will check it late
        ///     : because "nonce" still OPTIONAL in some case, so I will use it when it's provided for identity server
        /// </summary>
        public Parameter Nonce { get; private set; }
        public Parameter Email { get; private set; }
        public Parameter FirstName { get; private set; }
        public Parameter LastName { get; private set; }
        public Parameter Roles { get; private set; }
        public Parameter Gender { get; private set; }
        #endregion

#pragma warning disable CS8618 // Non-nullable field must contain a non-null value when exiting constructor. Consider declaring as nullable.
        public RegisterParameters(string? queryString, IHeaderDictionary headers) : base(queryString)
#pragma warning restore CS8618 // Non-nullable field must contain a non-null value when exiting constructor. Consider declaring as nullable.
        {
            UserName = new Parameter(RegisterRequest.UserName, RequestPurpose.Register);
            Password = new Parameter(RegisterRequest.Password, RequestPurpose.Register);

            string? userCredential = headers[RegisterRequest.Register][0];
            SetUserNameAndPassword(userCredential);
        }

        private void ValidateHeader(string? userCredential)
        {
            if (string.IsNullOrEmpty(userCredential))
                throw new CustomException(400, ExceptionMessage.REGISTER_INFORMATION_NULL_OR_EMPTY);
        }

        private void SetUserNameAndPassword(string? userCredential)
        {
            ValidateHeader(userCredential);

            var userNamePassword = userCredential.Replace(IdentityServerConfiguration.AUTHENTICATION_SCHEME_BASIC, "").Trim().ToBase64Decode();

            // TODO: will need to validate username and password, from client and server
            string userName = userNamePassword.Split(":")[0];
            string password = userNamePassword.Split(":")[1];

            UserName.SetValue(userName);
            Password.SetValue(password);
        }
    }
}
