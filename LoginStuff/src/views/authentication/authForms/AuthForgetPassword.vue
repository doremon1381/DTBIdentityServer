<script lang="ts">
import { router } from '@/router';
import { useAxiosGet, webServerTestRequest } from '@/extensions/RequestUltilities';
import { AxiosHeaders } from 'axios';
import { GenerateRandomStringWithLength } from '@/extensions/RNGCryptoUltilities';

let forgotPasswordUri = "";

export default {
    data () {
        return {
            email:'doremon1381@gmail.com',
            Regform:'',
            emailRules: [(v) => !!v || 'E-mail is required', (v) => /.+@.+\..+/.test(v) || 'E-mail must be valid']
        }
    },
    methods:{
        ForgetPassword(){
            console.log(this.email);
            useAxiosGet(webServerTestRequest.value + '/auth/forgotPassword', (response) => {
                const headers = response.headers;
                if (headers instanceof AxiosHeaders && headers.has('location')) {
                    // TODO: from client: client_id, redirect_uri, nonce, code_challenge, code_challenge_method, client_state
                    //     : adding missing property into uri
                    forgotPasswordUri = headers["location"] + "&email=" + this.email;
                    console.log("id server: " + forgotPasswordUri);                   
                }
            },()=>{
                useAxiosGet(forgotPasswordUri, response => {
                    console.log(response);
                    router.push({name:'Change Password', state:{ forgotPasswordUri: forgotPasswordUri }});
                });
            });
        }
    }
}
</script>

<template>
    <v-form ref="Regform" lazy-validation action="/dashboards/analytical" class="mt-7 loginForm">
        <v-text-field
            v-model="email"
            :rules="emailRules"
            label="Email"
            class="mt-4 mb-4"
            required
            density="comfortable"
            hide-details="auto"
            variant="outlined"
            color="primary"
        ></v-text-field>
        <v-btn color="secondary" block class="mt-2" variant="flat" size="large" @click="ForgetPassword()">Forget Password</v-btn>
    </v-form>
    <div class="mt-5 text-right">
        <v-divider />
        <v-btn variant="plain" to="/auth/login" class="mt-2 text-capitalize mr-n2">Back to login!</v-btn>
    </div>
</template>