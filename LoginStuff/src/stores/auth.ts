import { defineStore } from 'pinia';
import { router } from '@/router';
import { useRouter } from 'vue-router';
import {
  StringUTF8ToByteArray,
  ByteArrayToBase64,
  GenerateRandomStringWithLength,
  Base64ToString
} from '@/extensions/RNGCryptoUltilities.js';
//import { useStore } from 'vuex'
import { useAxiosGetWithHeaders, useAxiosPostWithHeaders } from '@/extensions/RequestUltilities';
import { LoginEndpoint, RegisterEndpoint } from '@/extensions/IdentityServer';
import { useAuthenticationParametersStore } from '../stores/AuthenticationFlow';
import type { LocationQuery, LocationQueryValue } from 'vue-router';
import { AuthorizeRequest, OauthEndpoint } from '../stores/Utilities';

// const authorizeEndpoint = "https://localhost:7180/oauth2/authorize";
// const clientId = "ManagermentServer";

// const baseUrl = `${import.meta.env.VITE_API_URL}/users`;

// const router1 = useRouter();
// const body = router1.query;
// console.log(body);

function ValidateState(incomingState: string, currentState: string) {
  if (incomingState !== currentState) {
    return false;
  } else return true;
}

function parseJwt(token: string) {
  const base64Url = token.split('.')[1];
  const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
  const jsonPayload = decodeURIComponent(
    window
      .atob(base64)
      .split('')
      .map(function (c) {
        return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
      })
      .join('')
  );

  return JSON.parse(jsonPayload);
}

function IsGoingToAuthorizeEndpoint(endpoint: LocationQueryValue | LocationQueryValue[]): boolean {
  //console.log("is authorize endpoint: " + (endpoint !== 'oauth2/authorize'));
  return endpoint === '/oauth2/authorize';
}

function CreateLoginUri(uri: string, path: string): string {
  return `${uri}?path=${path}`;
}

function SendTokenRequest(user, path: string, prompt: string) {
  useAxiosPostWithHeaders(
    OauthEndpoint.AuthorizeEndpoint,
    {
      Authorization: `id_token ${user}`
    },
    `${Base64ToString(path)}&consent_granted=${prompt}`,
    (response) => {
      console.log(response);
      router.push('/close-tab');
    },
    undefined,
    (error) => {
      console.log(error);
      // TODO: for now
      router.push('/close-tab');
    }
  );
}

function redirectToConsentView(user) {
  const path = useAuthenticationParametersStore().path;

  const params = Base64ToString(path);
  const prompt = params
    .split('&')
    .find((q) => q.startsWith('prompt'))
    ?.replace('prompt=', '');

  if (prompt === 'none') {
    SendTokenRequest(user, path, prompt);
  } else if (prompt === 'login') {
    // TODO: for now, in this step, it is already inside login process, will think about openid oauth flow later
  } else if (prompt === 'consent') {
    //Open consent view if prompt="consent" inside request
    router.push(`/oauth/consent?path=${path}`);
  } else if (prompt === 'select_account') {
    // TODO: ignore this part for now, will update later
  } else {
    return;
  }
}

export const useAuthStore = defineStore({
  id: 'auth',
  state: () => {
    return {
      // initialize state from local storage to enable user to stay logged in
      /* eslint-disable-next-line @typescript-eslint/ban-ts-comment */
      // @ts-ignore
      user: JSON.parse(localStorage.getItem('user')),
      returnUrl: null
    };
  },
  actions: {
    login(username: string, password: string, query: LocationQuery) {
      if (!IsGoingToAuthorizeEndpoint(query.path))
        // TODO: need to catch exception and show dialog, but for now, ignore that part
        return;
      const useAuthenticationFlow = useAuthenticationParametersStore();

      const authorization = ByteArrayToBase64(StringUTF8ToByteArray(username + ':' + password));
      //const queryString = ConvertLocationQueryToString(query);

      // incomingQueryParamtersAsBase64 = ByteArrayToBase64(StringUTF8ToByteArray(queryString));
      // useAuthenticationFlow.path = incomingQueryParamtersAsBase64;

      // return user_code and redirect to device authentication?
      useAxiosPostWithHeaders(
        `${LoginEndpoint}`,
        {
          Authorization: 'Basic ' + authorization
        },
        `path=${useAuthenticationFlow.path}`,
        (response) => {
          if (response.status === 200) {
            // save to local storage part of
            // store user details and jwt in local storage to keep user logged in between page refreshes
            // TODO: need to verify jwt token by public key later
            localStorage.setItem('user', JSON.stringify(response.data));
            //console.log(localStorage.getItem('user'));
            redirectToConsentView(this.user);
          }
        }
      );
    },
    signUp(name: string, fullName: string, username: string, password: string, email: string, gender: string, address: string) {
      const authorization = ByteArrayToBase64(StringUTF8ToByteArray(username + ':' + password));
      const registerState = GenerateRandomStringWithLength(32);
      const uri =
        RegisterEndpoint +
        '&state=' +
        registerState +
        '&prompt=create&scope=openid%20profile%20email%20address%20offline_access' +
        '&name=' +
        encodeURI(name) +
        '&fullname=' +
        encodeURI(fullName) +
        '&email=' +
        email +
        '&gender=' +
        gender +
        '&address=' +
        address;
      useAxiosGetWithHeaders(
        uri,
        {
          Register: 'Basic ' + authorization
        },
        (response) => {
          if (ValidateState(response.data.state, registerState)) {
            // TODO: show alert, but currently not have
            //router.push('/auth/login');
            router.push(this.returnUrl || '/auth/login');
          }
          console.log('incoming state is not valid');
        }
      );
    },
    logout() {}
    // redirectToConsentView() {
    //   redirectToConsentView(this.user);
    // }
  }
});
