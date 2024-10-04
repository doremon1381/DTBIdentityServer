namespace IssuerOfClaims.Models
{
    public record class JwtOptions(
        string Issuer,
        string Audience,
        string Key,
        int ExpirationSeconds
    );
}
