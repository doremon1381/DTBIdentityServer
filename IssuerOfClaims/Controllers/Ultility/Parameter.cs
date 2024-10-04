using IssuerOfClaims.Extensions;
using static ServerUltilities.Identity.Constants;
using static ServerUltilities.Identity.OidcConstants;

namespace IssuerOfClaims.Controllers.Ultility
{
    public class Parameter
    {
        public string Name { get; private set; } = string.Empty;
        public string Value { get; private set; } = string.Empty;

        public ParameterPriority Priority { get; private set; } = ParameterPriority.OPTIONAL;

        public bool HasValue => !string.IsNullOrEmpty(this.Value);

        public Parameter(string name)
        {
            this.Name = name;
            SetParameterPriority();
        }

        public void SetValue(string value)
        {
            VerifyRequiredParameter(value);
            this.Value = value;
        }

        private bool VerifyRequiredParameter(string value)
        {
            if (this.Priority == ParameterPriority.REQRUIRED)
            {
                if (string.IsNullOrEmpty(value))
                    throw new InvalidDataException($"{this.Name} : {ExceptionMessage.REQUIRED_PARAMETER_NOT_NULL}");
            }

            return true;
        }

        private void SetParameterPriority()
        {
            if (DefaultParameterPriority.ContainsKey(this.Name))
            {
                this.Priority = DefaultParameterPriority[this.Name];
            }
            else if (RegisterParamterPriority.ContainsKey(this.Name))
            {
                this.Priority = RegisterParamterPriority[this.Name];
            }
            else
            {
                throw new InvalidDataException($"{this.Name} : Parameter priority is not set!");
            }
        }

        private static Dictionary<string, ParameterPriority> DefaultParameterPriority = new Dictionary<string, ParameterPriority>()
        {
            { AuthorizeRequest.Scope, ParameterPriority.REQRUIRED },
            { AuthorizeRequest.ResponseType, ParameterPriority.REQRUIRED },
            { AuthorizeRequest.ClientId, ParameterPriority.REQRUIRED },
            { AuthorizeRequest.RedirectUri, ParameterPriority.REQRUIRED },
            { AuthorizeRequest.State, ParameterPriority.RECOMMENDED },
            { AuthorizeRequest.CodeChallenge, ParameterPriority.OPTIONAL },
            { AuthorizeRequest.CodeChallengeMethod, ParameterPriority.OPTIONAL },
            { AuthorizeRequest.Nonce, ParameterPriority.OPTIONAL },
            { AuthorizeRequest.ResponseMode, ParameterPriority.OPTIONAL },
            { AuthorizeRequest.Prompt, ParameterPriority.OPTIONAL },
            { AuthorizeRequest.MaxAge, ParameterPriority.OPTIONAL },
            { AuthorizeRequest.UiLocales, ParameterPriority.OPTIONAL },
            { AuthorizeRequest.IdTokenHint, ParameterPriority.OPTIONAL }
        };

        private Dictionary<string, ParameterPriority> RegisterParamterPriority = new Dictionary<string, ParameterPriority>()
        {
            { RegisterRequest.UserName, ParameterPriority.REQRUIRED },
            { RegisterRequest.Password, ParameterPriority.REQRUIRED },
            { RegisterRequest.FirstName, ParameterPriority.OPTIONAL },
            { RegisterRequest.LastName, ParameterPriority.OPTIONAL },
            { RegisterRequest.Email, ParameterPriority.OPTIONAL },
            { RegisterRequest.Gender, ParameterPriority.OPTIONAL },
            { RegisterRequest.Phone, ParameterPriority.OPTIONAL},
            { RegisterRequest.Roles, ParameterPriority.OPTIONAL }
        };
    }
    public enum ParameterPriority
    {
        OPTIONAL,
        REQRUIRED,
        RECOMMENDED
    }
}
