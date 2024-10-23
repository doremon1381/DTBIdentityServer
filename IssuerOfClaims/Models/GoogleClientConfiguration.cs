namespace IssuerOfClaims.Models
{
    public record class GoogleClientConfiguration
    (
        string ClientId,
        string ProjectId,
        string AuthUri,
        string TokenUri,
        string UserInfoUri,
        string auth_provider_x509_cert_url,
        string ClientSecret,
        List<string> RedirectUris
    );
}
