<script setup lang="ts">
import GoogleImg from '@/assets/images/auth/social-google.svg'
import { defineProps } from 'vue';
import { GenerateRandomStringWithLength } from '@/extensions/RNGCryptoUltilities';
import { googleSdkLoaded } from "vue3-google-login"
import { useAxiosPostWithHeaders } from '@/extensions/RequestUltilities';
import { OauthEndpoint } from '@/stores/Utilities';
import { router } from '@/router';

const state = GenerateRandomStringWithLength(32);

const props = defineProps<{
    redirect_uri: string,
    client_id: string,
    nonce: string
}>();

function GoogleCallback(response) {
    // send request to server, send along redirect uri
    console.log("code", response.code);
    var uri = `code=${response.code}`
        + `&state=${state}&client_id=${props.client_id}`
        + `&grant_type=authorization_code&redirect_uri=${props.redirect_uri}`;
    console.log(uri);

    useAxiosPostWithHeaders(OauthEndpoint.GoogleEndpoint, {
        Accept: "Accept=text/html,application/xhtml+xml,application/xml;q=0.9,*;q=0.8"
    }, uri, (res) => {
        console.log(res);
        router.push('/close-tab');
    }, undefined, (error) => {
        console.log(error);
        //router.push('/close-tab');
    });
}

function RequestToGoogle() {
    googleSdkLoaded((google) => {
        google.accounts.oauth2.initCodeClient({
            client_id: '558160357396-q5qp0ppf4r5svc0g0smshfs8cdcffkm3.apps.googleusercontent.com',
            state: state,
            redirect_uri: props.redirect_uri,
            scope: decodeURI('openid%20profile%20email'),
            ux_mode: "popup",
            callback: (response) => GoogleCallback(response)
        }).requestCode();
    });
}

</script>
<template>
    <v-btn @click="RequestToGoogle" block color="primary" variant="outlined" class="text-lightText googleBtn">
        <img :src="GoogleImg" alt="google" />
        <span class="ml-2">Sign in with Google</span>
    </v-btn>
</template>