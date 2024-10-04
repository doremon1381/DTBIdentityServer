using ServerUltilities.Identity;

namespace IssuerOfClaims.Database.Model
{
    public static class IdentityExtensions
    {

        /// <summary>
        /// Validates the grant types.
        /// </summary>
        /// <param name="grantTypes">The grant types.</param>
        /// <exception cref="System.InvalidOperationException">
        /// Grant types list is empty
        /// or
        /// Grant types cannot contain spaces
        /// or
        /// Grant types list contains duplicate values
        /// </exception>
        public static void ValidateGrantTypes(IEnumerable<string> grantTypes)
        {
            if (grantTypes == null)
            {
                throw new ArgumentNullException(nameof(grantTypes));
            }

            // spaces are not allowed in grant types
            foreach (var type in grantTypes)
            {
                if (type.Contains(' '))
                {
                    throw new InvalidOperationException("Grant types cannot contain spaces");
                }
            }

            // single grant type, seems to be fine
            if (grantTypes.Count() == 1) return;

            // don't allow duplicate grant types
            if (grantTypes.Count() != grantTypes.Distinct().Count())
            {
                throw new InvalidOperationException("Grant types list contains duplicate values");
            }

            // would allow response_type downgrade attack from code to token
            DisallowGrantTypeCombination(GrantType.Implicit, GrantType.AuthorizationCode, grantTypes);
            DisallowGrantTypeCombination(GrantType.Implicit, GrantType.Hybrid, grantTypes);

            DisallowGrantTypeCombination(GrantType.AuthorizationCode, GrantType.Hybrid, grantTypes);
        }

        private static void DisallowGrantTypeCombination(string value1, string value2, IEnumerable<string> grantTypes)
        {
            if (grantTypes.Contains(value1, StringComparer.Ordinal) &&
                grantTypes.Contains(value2, StringComparer.Ordinal))
            {
                throw new InvalidOperationException($"Grant types list cannot contain both {value1} and {value2}");
            }
        }
    }
}
