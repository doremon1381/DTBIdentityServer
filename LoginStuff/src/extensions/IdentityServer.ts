const identityServerUri = 'https://localhost:7180';
const ClientId = "ManagermentServer";
const LoginEndpoint = `${identityServerUri}/auth/signin`;
const RegisterEndpoint = `${identityServerUri}/auth/register`;
const AuthorizeEndpoint = `${identityServerUri}/oauth2/authorize`;

export {
    AuthorizeEndpoint,
    ClientId,
    LoginEndpoint,
    RegisterEndpoint
}