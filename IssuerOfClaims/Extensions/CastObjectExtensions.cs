namespace IssuerOfClaims.Extensions
{
    public static class CastObjectExtensions
    {
        public static E Cast<E>(this object instance, E obj)
        {
            return (E) instance;
        }
    }
}
