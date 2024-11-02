namespace IssuerOfClaims.Extensions
{
    public static class IEnumerableExtensions
    {
        public static bool IsNullOrEmpty<T>(this IEnumerable<T> list)
        {
            if (list == null)
            {
                return true;
            }

            if (!list.Any())
            {
                return true;
            }

            return false;
        }

        /// <summary>
        /// Assuming in auth request, after path, always is a string with form is "{query symbol (?) or fragment symbol (#)}{parameters and value}"
        /// <para>Example: https://server.example.com/authorize?response_type=code&scope=openid%20profile%20email&client_id=s6BhdRkqt3&state=af0ifjsldkj&redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb</para>
        /// </summary>
        /// <param name="queryString"></param>
        /// <returns></returns>
        public static string RemoveQueryOrFragmentSymbol(this string queryString)
        {
            return queryString.Remove(0, 1);
        }
    }
}
