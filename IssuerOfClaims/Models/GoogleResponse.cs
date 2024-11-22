namespace IssuerOfClaims.Models
{
    public record GoogleResponse(
        string AccessToken, 
        string IdToken, 
        string RefreshToken, 
        DateTime AccessTokenIssueAt, 
        double ExpiredIn);
}
