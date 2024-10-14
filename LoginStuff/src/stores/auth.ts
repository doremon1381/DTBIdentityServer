import { defineStore } from 'pinia';
import { router } from '@/router';
//import { fetchWrapper } from '@/utils/helpers/fetch-wrapper';
import { AxiosHeaders } from 'axios';
import { StringUTF8ToByteArray, ByteArrayToBase64, GenerateRandomStringWithLength } from '@/extensions/RNGCryptoUltilities.js';
//import { useIdentityOptions } from '@/stores/identityOptions';
//import { tokenVerifyer } from '@/stores/JwtValidate';
//import { mapMutations } from 'vuex'
//import { useStore } from 'vuex'
import { useAxiosGet, useAxiosGetWithHeaders } from '@/extensions/RequestUltilities';

// const authorizeEndpoint = "https://localhost:7180/oauth2/authorize";
//const redirecUri = "https://localhost:7209/auth/callback";
// const clientId = "PrintingManagermentServer";

// const baseUrl = `${import.meta.env.VITE_API_URL}/users`;
const authState :string = GenerateRandomStringWithLength(32);
const registerState :string = GenerateRandomStringWithLength(32);
//const store = useStore();

function ValidateState(incomingState: string, currentState: string)
{
    if (incomingState !== currentState)
    {
      return false;
    }
    else 
      return true;
}

function parseJwt (token: string) {
  const base64Url = token.split('.')[1];
  const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
  const jsonPayload = decodeURIComponent(window.atob(base64).split('').map(function(c) {
      return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
  }).join(''));

  return JSON.parse(jsonPayload);
}

//const identityOptions = useIdentityOptions();
//const authorizationCodeResponse = ref(null);
let clientState = "";
let authCodeUri = "";
let accessTokenUri= "";
let registerUri = "";
const identityServerUri = "https://localhost:7180";

export const useAuthStore = defineStore({
  id: 'auth',
  state: () => {
    return {
      // initialize state from local storage to enable user to stay logged in
      /* eslint-disable-next-line @typescript-eslint/ban-ts-comment */
      // @ts-ignore
      user: JSON.parse(localStorage.getItem('user')),
      returnUrl: null
    }
  },
  actions: {
    async login(username: string, password: string) {
      // const user = await fetchWrapper.post(`${baseUrl}/authenticate`, { username, password });
      const authorization = ByteArrayToBase64(StringUTF8ToByteArray(username + ":" + password));
      //const authorizationRequest = authorizeEndpoint + "?response_type=code&scope=openid%20profile%20email%20offline_access&redirect_uri=" + redirecUri + "&client_id="+ clientId + "&state=" + state;
      
      useAxiosGetWithHeaders(authCodeUri, {
        Authorization: "Basic "+ authorization
      }, response => {
      //authorizationCodeResponse.value = response.data.code;  
      // console.log(response.data.location);
      if(!ValidateState(response.data.state, authState))
      {
        console.log("incoming state is not valid");
        router.push('/auth/login');
      }
      const headers = response.headers;
      //console.log(headers);
      if (headers instanceof AxiosHeaders && headers.has('location')) {
          accessTokenUri = headers["location"] + "&client_state=" + clientState + "&state=" + authState;
          console.log(accessTokenUri);
      }
    }, ()=>{
      // useAxiosGet(accessTokenUri, response => {
      //   const user = parseJwt(response.data);
      //   user.access_token = response.data;
      //   // TODO: do it later
      //   //const isVerified = tokenVerifyer(response.data);
      //   // update pinia state
      //   this.user = user;
      //   // store user details and jwt in local storage to keep user logged in between page refreshes
      //   localStorage.setItem('user', JSON.stringify(user));
      //   // redirect to previous url or default to home page
      //   router.push(this.returnUrl || '/dashboard/default');
      // })
    })
    },
    logout() {
      this.user = null;
      localStorage.removeItem('user');
      router.push('/auth/login');
    },
    async signUp(name: string, fullName: string, username: string , password: string, email: string, gender: string){
      const authorization = ByteArrayToBase64(StringUTF8ToByteArray(username + ":" + password));

      useAxiosGet(identityServerUri, response => {
        let location = "";
        const headers = response.headers;

        if (headers instanceof AxiosHeaders && headers.has('location')) {
          location = headers["location"];
          
          registerUri = location + "&state=" + registerState + 
            "&prompt=create&scope=openid%20profile%20email%20offline_access" + 
            "&name=" + encodeURI(name) + 
            "&fullname=" + encodeURI(fullName) + 
            "&email=" + email + 
            "&gender=" + gender;
          // console.log("id server: " + authCodeRequest);

          clientState = response.data.client_state;
          // console.log("clientState: " + clientState.value);
        }},() => {
          useAxiosGetWithHeaders(registerUri, {
              "Register": "Basic "+ authorization
            }, response => {
            // console.log(response.data.location);
            if(ValidateState(response.data.state, registerState))
            {
              // TODO: show alert, but currently not have
              //router.push('/auth/login');
              router.push(this.returnUrl || '/auth/login');
            }
            console.log("incoming state is not valid");
          });            
      })
    }
  }
});
