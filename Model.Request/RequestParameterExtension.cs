using static ServerUltilities.Identity.Constants;
using static ServerUltilities.Identity.OidcConstants;
using System.Reflection;
using System.Net;
using IssuerOfClaims.Models.Request.RequestParameter;
using ServerUltilities;
using ServerUltilities.Extensions;

namespace IssuerOfClaims.Models.Request
{
    public static class RequestParameterExtension
    {
        private static readonly Type _registerRequestType = typeof(RegisterRequest);
        private static readonly Type _authorizeRequestType = typeof(AuthorizeRequest);
        private static readonly Type _signInGoogleRequestType = typeof(SignInGoogleRequest);
        private static readonly Type _changePasswordRequestType = typeof(ChangePasswordRequest);
        private static readonly Type _forgotPasswordRequestType = typeof(ForgotPasswordRequest);
        private static readonly Type _tokenRequestType = typeof(TokenRequest);
        //private static readonly Type _hybridRequestType = typeof(HybridRequest);

        public static FieldInfo[] ParameterNames(Type type)
        {
            return type.Name switch
            {
                nameof(AuthCodeParameters) => _authorizeRequestType.GetFields(
                    // Gets all public and static fields
                    BindingFlags.Public | BindingFlags.Static |
                    // This tells it to get the fields from all base types as well
                    BindingFlags.FlattenHierarchy),
                nameof(RegisterParameters) => _registerRequestType.GetFields(
                    // Gets all public and static fields
                    BindingFlags.Public | BindingFlags.Static),
                nameof(SignInGoogleParameters) => _signInGoogleRequestType.GetFields(
                    BindingFlags.Public | BindingFlags.Static),
                nameof(AuthCodeTokenParameters) => _tokenRequestType.GetFields(
                    BindingFlags.Public | BindingFlags.Static),
                nameof(OfflineAccessTokenParameters) => _tokenRequestType.GetFields(
                    BindingFlags.Public | BindingFlags.Static),
                nameof(ChangePasswordParameters) => _changePasswordRequestType.GetFields(
                    BindingFlags.Public | BindingFlags.Static),
                nameof(ForgotPasswordParameters) => _forgotPasswordRequestType.GetFields(
                    BindingFlags.Public | BindingFlags.Static),
                //nameof(HybridParameters) => _hybridRequestType.GetFields(
                //    BindingFlags.Public & BindingFlags.Static),
                // TODO: will check it later
                _ => throw new InvalidOperationException()
            };
        }
    }

    public static class QueryParametersValidation
    {
        public static void ValidateAuthCodeParameters(AuthCodeParameters parameters)
        {
            Validate(parameters);

            #region validation
            void Validate(AuthCodeParameters parameters)
            {
                ValidateScope(parameters.Scope);
                ValidatePKCEParameters(parameters.CodeChallenge, parameters.CodeChallengeMethod);
                ValidateResponseType(parameters.ResponseType);
                ValidatePrompt(parameters.Prompt, parameters.ConsentGranted);
            }

            void ValidatePrompt(Parameter prompt, Parameter consentGranted)
            {
                // TODO: will check again
                if (prompt.HasValue)
                {
                    if (!SupportedPromptModes.Contains(prompt.Value))
                        throw new CustomException(ExceptionMessage.PROMPT_VALUE_NOT_VALID, HttpStatusCode.BadRequest);
                    if (prompt.Value.Equals(PromptModes.Consent) && !SupportConsentGrantedValue.Contains(consentGranted.Value))
                        throw new CustomException(ExceptionMessage.PROMPT_CONSENT_VALUE_NOT_VALID, HttpStatusCode.BadRequest);
                }
            }

            void ValidateScope(Parameter scope)
            {
                if (!scope.Value.Contains(StandardScopes.OpenId))
                    throw new CustomException(ExceptionMessage.AUTHORIZE_SCOPES_MUST_HAVE_OPENID, HttpStatusCode.BadRequest);
            }

            void ValidatePKCEParameters(Parameter codeChallenge, Parameter codeChallengeMethod)
            {
                if (codeChallengeMethod.HasValue && !codeChallenge.HasValue
                    || codeChallenge.HasValue && !codeChallengeMethod.HasValue)
                    throw new CustomException(ExceptionMessage.CODECHALLENGE_CODECHALLENGEMETHOD_NOT_HAVE_VALUE_SIMUTANEOUSLY, HttpStatusCode.BadRequest);
            }

            /// <summary>
            /// TODO: must be used after ResponseType has value
            /// </summary>
            /// <exception cref="InvalidDataException"></exception>
            void ValidateResponseType(Parameter responseType)
            {
                if (!SupportedResponseTypes.Contains(responseType.Value))
                    throw new CustomException(ExceptionMessage.RESPONSE_TYPE_NOT_SUPPORTED, HttpStatusCode.BadRequest);
            }
            #endregion
        }
    }
}
