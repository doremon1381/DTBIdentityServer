namespace IssuerOfClaims.Extensions
{
    public static class ExceptionMessage
    {
        public const string USER_NULL = "User at this step cannot be null!";
        public const string SCOPES_NOT_ALLOWED = "Scopes is not allowed!";
        public const string AUTHORIZE_SCOPES_MUST_HAVE_OPENID = "Authorize request scopes must have openid!";
        public const string INVALID_CLIENTID = "Invalid client id!";
        public const string REQUEST_BODY_NOT_NULL_OR_EMPTY = "Request body cannot be empty!";
        public const string QUERYSTRING_NOT_NULL_OR_EMPTY = "Query string cannot be empty!";

        public const string REFRESH_TOKEN_NULL = "Refresh token can not be empty!";
        public const string REQUIRED_PARAMETER_NOT_NULL = "Required parameter cannot be null!";

        public const string CLIENTID_IS_REQUIRED = "ClientId is required!";
        public const string CLIENTID_NOT_FOUND = "ClientId did not found!";
        public const string REDIRECTURI_IS_REQUIRED = "RedirectUri is required!";
        public const string REDIRECTURI_IS_MISMATCH = "RedirectUri is mismatch!";

        public const string REGISTER_INFORMATION_NULL_OR_EMPTY = "Register's information is null or empty!";

        public const string RESPONSE_TYPE_NOT_SUPPORTED = "Response type is not supported!";

        public const string USER_ALREADY_EXISTS = "username or email is already exist!";

        public const string OBJECT_IS_NULL = "Object is null!";
        public const string OBJECT_NOT_FOUND = "Object is not found!";
        public const string REFRESH_TOKEN_EXPIRED = "Refresh token is expired!";
        public const string RESPONSE_MODE_NOT_ALLOWED = "Response mode is not allowed!";
        public const string EMAIL_IS_MISSING = "email is missing!";
        public const string EMAIL_IS_EXPIRED = "email is expired!";
        public const string NOT_IMPLEMENTED = "Not implemented!";
        public const string UNKNOW_ERROR = "Not yet know error!";
        public const string EMAIL_CONFIRM_CODE_NOT_MATCH = "Confirm code is not match!";

        public const string CODECHALLENGE_CODECHALLENGEMETHODE_NOT_HAVE_VALUE_SIMUTANEOUSLY = "Code challenge does not have value simutaneosly with code challenge method or vice versa!";
    }
}
