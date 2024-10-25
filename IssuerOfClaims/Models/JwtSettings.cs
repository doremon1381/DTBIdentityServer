namespace IssuerOfClaims.Models
{
    public record class JwtSettings(
        string Issuer,
        string Audience,
        string Key,
        int ExpirationSeconds
    );
}
