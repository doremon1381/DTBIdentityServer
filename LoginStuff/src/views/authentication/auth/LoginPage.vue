<script setup lang="ts">
import Logo from '@/layouts/full/logo/LogoDark.vue';
import AuthLogin from '../authForms/AuthLogin.vue';
import { useRouter } from 'vue-router';
//import { ref } from 'vue';
import { router } from '@/router'
import { useAuthenticationParametersStore } from '@/stores/AuthenticationFlow';
import { onMounted, onBeforeMount } from 'vue';
import { ByteArrayToBase64, StringUTF8ToByteArray } from '@/extensions/RNGCryptoUltilities';
import type { LocationQuery } from 'vue-router';
import { AuthorizeRequest } from '@/stores/Utilities';

const request = useRouter();
console.log(request.currentRoute.value.query);

function ConvertLocationQueryToString(query: LocationQuery): string {
  const temp =
    `${AuthorizeRequest.ResponseType}=${query.response_type}` +
    `&${AuthorizeRequest.ResponseMode}=${query.response_mode === undefined ? '' : query.response_mode}` +
    `&${AuthorizeRequest.Scope}=${encodeURI(query.scope)}` +
    `&${AuthorizeRequest.RedirectUri}=${query.redirect_uri}` +
    `&${AuthorizeRequest.ClientId}=${query.client_id}` +
    `&${AuthorizeRequest.State}=${query.state}` +
    `&${AuthorizeRequest.CodeChallenge}=${query.code_challenge}` +
    `&${AuthorizeRequest.CodeChallengeMethod}=${query.code_challenge_method}` +
    `&${AuthorizeRequest.Prompt}=${query.prompt}` +
    `&${AuthorizeRequest.Nonce}=${query.nonce}`;

  return temp;
}

const query = request.currentRoute.value.query;
if (query.path !== "/oauth2/authorize")
  router.push('/pages/error');

onBeforeMount(async () => {
  const useAuthenticationFlow = useAuthenticationParametersStore();
  const queryString = ConvertLocationQueryToString(query);

  const temp = ByteArrayToBase64(StringUTF8ToByteArray(queryString));
  useAuthenticationFlow.path = temp;
})

</script>

<template>
  <v-row class="h-screen" no-gutters>
    <!---Left Part-->
    <v-col cols="12" class="d-flex align-center bg-lightprimary">
      <v-container>
        <div class="pa-7 pa-sm-12">
          <v-row justify="center">
            <v-col cols="12" lg="10" xl="6" md="7">
              <v-card elevation="0" class="loginBox">
                <v-card variant="outlined">
                  <v-card-text class="pa-9">
                    <!---Left Part Logo -->
                    <v-row>
                      <v-col cols="12" class="text-center">
                        <Logo />
                        <h2 class="text-secondary text-h2 mt-8">Hi, Welcome Back</h2>
                        <h4 class="text-disabled text-h4 mt-3">Enter your credentials to continue</h4>
                      </v-col>
                    </v-row>
                    <!---Left Part Logo -->

                    <!---Left Part Form-->
                    <AuthLogin :query="query" />
                    <!---Left Part Form-->
                  </v-card-text>
                </v-card>
              </v-card>
            </v-col>
          </v-row>
        </div>
      </v-container>
    </v-col>
    <!---Left Part-->
  </v-row>
</template>
<style lang="scss">
.loginBox {
  max-width: 475px;
  margin: 0 auto;
}
</style>
