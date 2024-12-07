class NormalOauthFlow {
  static AuthorizationCode = 'authorization_code';
  static Implicit = 'implicit';
  static Hybrid = 'hybrid';
}

class AuthorizeRequest {
  static Scope = 'scope';
  static ResponseType = 'response_type';
  static ClientId = 'client_id';
  static RedirectUri = 'redirect_uri';
  static State = 'state';
  static ResponseMode = 'response_mode';
  static Nonce = 'nonce';
  static Display = 'display';
  static Prompt = 'prompt';
  static MaxAge = 'max_age';
  static UiLocales = 'ui_locales';
  static IdTokenHint = 'id_token_hint';
  static LoginHint = 'login_hint';
  static AcrValues = 'acr_values';
  static CodeChallenge = 'code_challenge';
  static CodeChallengeMethod = 'code_challenge_method';
  static Request = 'request';
  static RequestUri = 'request_uri';
  static Resource = 'resource';
  static DPoPKeyThumbprint = 'dpop_jkt';

  // TODO: use for redirect from login web to server
  static ConsentGranted = 'consent_granted';
}

class OauthEndpoint {
  static basicRoute = 'https://localhost:7180';
  static AuthorizeEndpoint = this.basicRoute + '/oauth2/authorize';
  static GoogleEndpoint = this.basicRoute + '/oauth2/authorize/google';
}

export { NormalOauthFlow, AuthorizeRequest, OauthEndpoint };
