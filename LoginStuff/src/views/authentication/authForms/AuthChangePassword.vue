<script lang="ts">
import { useAxiosGet } from '@/extensions/RequestUltilities';
import axios from 'axios';
import { GenerateRandomStringWithLength } from '@/extensions/RNGCryptoUltilities';
import { router } from '@/router';

const state :string = GenerateRandomStringWithLength(32);

export default {
        data () {
            return {
                expiredTime: 60,
                code:'',
                password:'',
                password1:'',
                passwordRules:'',
                Regform:'',
                show:false,
                show1:false
            }
        },
        methods: {
            countDownTimer () {
                if (this.expiredTime > 0) {
                    setTimeout(() => {
                        this.expiredTime -= 1
                        this.countDownTimer()
                    }, 1000)
                }
            },
            UpdatePassword(){
                console.log(history.state.forgotPasswordUri);
                var uri = history.state.forgotPasswordUri + "&state=" + state;
                if (this.password == this.password1){
                    axios.post(uri, {
                        code: this.code,
                        password: this.password
                    }).then(response =>{
                        if (response.status == 200)
                            router.push({ name:'Login', state:{} });
                        // TODO: check state, check id_token if it has, but for now, it does not
                    }).catch(error => {
                        console.log(error);
                    });
                }   
                else{
                    console.log("two password is not matched!");
                }             
            }
        },
        created () {
            this.countDownTimer()
        }
    }
</script>

<template>
  <h5 class="text-h5 ml-2 my-4 mb-8">Update your new password!</h5>
  <p class="ml-2">Please, check your email to get code</p>
    <span class="ml-2">Expired in </span><span style="color: rebeccapurple; font-weight: bold;">{{ expiredTime }}</span>
    <v-form ref="Regform" lazy-validation action="/dashboards/analytical" class="mt-7 loginForm">
        <v-text-field
            v-model="code"
            label="Code"
            class="mt-4 mb-4"
            required
            density="comfortable"
            hide-details="auto"
            variant="outlined"
            color="primary"
        ></v-text-field>
        <v-text-field
            v-model="password"
            :rules="passwordRules"
            label="New Password"
            class="mt-4 mb-4"
            required
            density="comfortable"
            variant="outlined"
            color="primary"
            hide-details="auto"
            :append-icon="show ? '$eye' : '$eyeOff'"
            :type="show ? 'text' : 'password'"
            @click:append="show = !show"
        ></v-text-field>
        <v-text-field
            v-model="password1"
            :rules="passwordRules"
            label="Enter new password again"
            class="mt-4 mb-4"
            required
            density="comfortable"
            hide-details="auto"
            variant="outlined"
            color="primary"
            :append-icon="show1 ? '$eye' : '$eyeOff'"
            :type="show1 ? 'text' : 'password'"
            @click:append="show1 = !show1"
        ></v-text-field>
        <v-btn color="secondary" block class="mt-2" variant="flat" size="large" @click="UpdatePassword()">Change Password</v-btn>
    </v-form>
    <div class="mt-5 text-right">
        <v-divider />
        <v-btn variant="plain" to="/auth/forgetPassword" class="mt-2 text-capitalize mr-n2">Back to forget password!</v-btn>
    </div>
</template>