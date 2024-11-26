namespace ServerUltilities.Extensions
{
    public static class ExceptionMessage
    {
        public const string USER_NULL = "User at this step cannot be null!";
        public const string SCOPES_NOT_ALLOWED = "Scopes is not allowed!";
        public const string AUTHORIZE_SCOPES_MUST_HAVE_OPENID = "Authorize request scopes must have openid!";
        public const string INVALID_CLIENTID = "Invalid client id!";
        public const string REQUEST_BODY_NOT_NULL_OR_EMPTY = "Request body cannot be empty!";
        public const string QUERYSTRING_NOT_NULL_OR_EMPTY = "Query string cannot be empty!";

        public const string REFRESH_TOKEN_NULL = "Refresh token is null or empty!";
        public const string REQUIRED_PARAMETER_NOT_NULL = "Required parameter cannot be null!";

        public const string CLIENTID_IS_REQUIRED = "ClientId is required!";
        public const string CLIENTID_NOT_FOUND = "ClientId did not found!";
        public const string REDIRECTURI_IS_REQUIRED = "RedirectUri is required!";
        public const string REDIRECTURI_IS_MISMATCH = "RedirectUri is mismatch!";

        public const string REGISTER_INFORMATION_NULL_OR_EMPTY = "Register's information is null or empty!";

        public const string RESPONSE_TYPE_NOT_SUPPORTED = "Response type is not supported!";

        public const string USER_ALREADY_EXISTS = "username or email is already exist!";
        public const string UNHANDLED_AUTHENTICATION_SCHEME = "Unhandled authentication scheme!";
        public const string IDENTITY_iNFO_MISSING_OR_MISMATCH = "username and password is missing or empty!";

        public const string OBJECT_IS_NULL = "Object is null!";
        public const string REQUEST_HEADER_MISSING_IDENTITY_INFO = "Authentication's identity inside request headers is missing!";
        public const string OBJECT_NOT_FOUND = "Object is not found!";
        public const string REFRESH_TOKEN_EXPIRED = "Refresh token is expired!";
        public const string RESPONSE_MODE_NOT_ALLOWED = "Response mode is not allowed!";
        public const string EMAIL_IS_MISSING = "email is missing!";
        public const string EMAIL_IS_WRONG = "email is wrong pattern!";
        public const string EMAIL_IS_EXPIRED = "email is expired!";
        public const string NOT_IMPLEMENTED = "Not implemented!";
        public const string WRONG_IMPLEMENTED = "Not implemented!";
        public const string WRONG_USERNAME_OR_PASSWORD = "Wrong username or password!";
        public const string CONFIRM_EMAIL_SEEM_WRONG = "something inside this process is wrong!";
        public const string CONFIRM_EMAIL_EXPIRED = "error with email's expired time!";
        public const string MISSING_GOOGLE_CLIENT_DETAILS = "Details of google's client is mismatch!";
        public const string MISSING_WEB_SIGIN_DETAILS = "Details of WebSignin's settings is mismatch!";
        public const string UNKNOW_ERROR = "Not yet know error!";
        public const string PASSWORD_NOT_SET = "User password is currently not set!";
        public const string PROMPT_VALUE_NOT_VALID = "Prompt's value is not valid!";
        public const string EMPTY_RESPONSE_TYPE = "Response type must have value while in hybrid flow process!";
        public const string EMPTY_NONCE = "Nonce must have value while in hybrid flow process!";
        public const string PROMPT_CONSENT_VALUE_NOT_VALID = "Value of prompt's consent is not valid!";
        public const string EMAIL_CONFIRM_CODE_NOT_MATCH = "Confirm code is not match!";
        public const string AUTHORIZATION_BASIC_NOT_SUPPORT_FOR_AUTHORIZE_ENDPOINT = "Authorization scheme is not support in this endpoint!";
        public const string NONCE_MUST_HAVE_VALUE_WITH_IMPLICIT_GRANT_FLOW = "In implicit grant flow, nonce must have value inside request query!";
        public const string AUTHENTICATION_SCHEME_NOT_SUPPORT = "Authentication scheme is not supported!";
        public const string AUTHENTICATION_INFORMATION_MISSING_OR_MISMATCH = "Authentication information is missing or mismatch!";

        public const string CODECHALLENGE_CODECHALLENGEMETHOD_NOT_HAVE_VALUE_SIMUTANEOUSLY = "Code challenge does not have value simutaneosly with code challenge method or vice versa!";
        public const string CODE_CHALLENGE_METHOD_NOT_SUPPORT = "Code challenge method does not supported!";
        public const string CODE_VERIFIER_MISMATCH = "code verifier is mismatch!";
        public const string CLIENT_OF_TOKEN_REQUEST_IS_DIFFERENT_WITH_AUTH_CODE_REQUEST = "something wrong with client which is associated with result from auth code request!";
    }
}
