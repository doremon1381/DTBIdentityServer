const identityServerUri = 'https://localhost:7180';
const ClientId = "ManagermentServer";
const LoginEndpoint = `${identityServerUri}/auth/signin`;
const RegisterEndpoint = `${identityServerUri}/auth/register`;
const AuthorizeEndpoint = `${identityServerUri}/oauth2/authorize`;

const GoogleClientId = "558160357396-q5qp0ppf4r5svc0g0smshfs8cdcffkm3.apps.googleusercontent.com";
export {
    AuthorizeEndpoint,
    ClientId,
    LoginEndpoint,
    RegisterEndpoint,
    GoogleClientId
}