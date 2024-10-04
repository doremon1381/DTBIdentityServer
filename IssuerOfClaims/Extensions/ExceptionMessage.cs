namespace IssuerOfClaims.Extensions
{
    public static class ExceptionMessage
    {
        public const string USER_NULL = "User at this step cannot be null!";
        public const string SCOPES_NOT_ALLOWED = "Scopes is not allowed!";
        public const string INVALID_CLIENTID = "Invalid client id!";
        public const string REQUEST_BODY_NOT_NULL_OR_EMPTY = "Request body cannot be empty!";
        public const string QUERYSTRING_NOT_NULL_OR_EMPTY = "Query string cannot be empty!";

        public const string REQUIRED_PARAMETER_NOT_NULL = "Required parameter cannot be null!";

        public const string CLIENTID_IS_REQUIRED = "ClientId is required!";
        public const string REDIRECTURI_IS_REQUIRED = "RedirectUri is required!";

        public const string REGISTER_INFORMATION_NULL_OR_EMPTY = "Register's information is null or empty!";

        public const string RESPONSE_TYPE_NOT_SUPPORTED = "Response type is not supported!";

        public const string CODECHALLENGE_CODECHALLENGEMETHODE_NOT_HAVE_VALUE_SIMUTANEOUSLY = "Code challenge does not have value simutaneosly with code challenge method or vice versa!";
    }
}
