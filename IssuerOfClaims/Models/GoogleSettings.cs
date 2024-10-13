﻿namespace IssuerOfClaims.Models
{
    public record class GoogleSettings
    (
        string ClientId,
        string ProjectId,
        string AuthUri,
        string TokenUri,
        string auth_provider_x509_cert_url,
        string ClientSecret,
        List<string> RedirectUris
    );
}