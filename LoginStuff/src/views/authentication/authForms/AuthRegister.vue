<script setup>
import { ref } from 'vue';
import Google from '@/assets/images/auth/social-google.svg';
import { useAuthStore } from '@/stores/auth';
const checkbox = ref(false);
const show1 = ref(false);
const password = ref('*Tinhte2024');
const email = ref('doremon1380@gmail.com');
const username = ref('doremon1397');
const Regform = ref();
const firstname = ref('Tuấn');
const lastname = ref('Nguyễn Văn');
const dateOfBirth = ref('08/11/1994');
const phone = ref('0366096986');
const address = ref('');
const gender = ref('male');
//const roles = ref('employee');
// const errorStr = ref('');
// const errorAlert = ref(false);
const passwordRules = ref([
  (v) => !!v || 'Password is required',
  //(v) => /([a-zA-Z0-9])({9,})/.test(v) || 'Password must be more than 10 characters'
]);
const userNameRules = ref([(v)=> !!v || "username is required!"]);
const emailRules = ref([(v) => !!v || 'E-mail is required', (v) => /.+@.+\..+/.test(v) || 'E-mail must be valid']);
const phoneRules = ref([(v) => /^(03|09)\d{8}$/.test(v) || "phone number must start with 03 or 09 and have 10 digits!"]);

// function validate() {
//   Regform.value.validate();
// }

function validate() {
  Regform.value.validate();
  const authStore = useAuthStore();
  //console.log(email.value);
  return authStore.signUp(firstname.value, firstname.value.trim() + " " + lastname.value.trimStart().trimEnd(), username.value, password.value, email.value, gender.value, address.value)
  .catch((error) => {console.log(error);});
}

// created(() => {
//   setTimeout(() => {
//     errorAlert.value = false
//   }, 5000)}
// ); 
</script>

<template>
  <template>
  <!-- <v-alert
    :text="errorStr"
    v-model="errorAlert"
    title="Alert title"
    color="error"
    icon="$error"
  ></v-alert> -->
</template>
  <!-- <v-btn block color="primary" variant="outlined" class="text-lightText googleBtn">
    <img :src="Google" alt="google" />
    <span class="ml-2">Sign up with Google</span></v-btn
  > -->
  <v-row>
    <v-col class="d-flex align-center">
      <v-divider class="custom-devider" />
      <!-- <v-btn variant="outlined" class="orbtn" rounded="md" size="small">OR</v-btn> -->
      <v-divider class="custom-devider" />
    </v-col>
  </v-row>
  <!-- <h5 class="text-h5 text-center my-4 mb-8">Sign up with Email address</h5> -->
  <v-form ref="Regform" lazy-validation action="/dashboards/analytical" class="mt-7 loginForm">
    <v-row>
      <v-col cols="12" sm="6">
        <v-text-field
          v-model="firstname"
          density="comfortable"
          hide-details="auto"
          variant="outlined"
          color="primary"
          label="Firstname"
        ></v-text-field>
      </v-col>
      <v-col cols="12" sm="6">
        <v-text-field
          v-model="lastname"
          density="comfortable"
          hide-details="auto"
          variant="outlined"
          color="primary"
          label="Lastname"
        ></v-text-field>
      </v-col>
    </v-row>
    <v-text-field
      v-model="username"
      :rules="userNameRules"
      label="Username"
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
      label="Password"
      required
      density="comfortable"
      variant="outlined"
      color="primary"
      hide-details="auto"
      :append-icon="show1 ? '$eye' : '$eyeOff'"
      :type="show1 ? 'text' : 'password'"
      @click:append="show1 = !show1"
      class="pwdInput"
    ></v-text-field>
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
    <v-text-field
      v-model="dateOfBirth"
      label="Date of birth"
      class="mt-4 mb-4"
      required
      density="comfortable"
      hide-details="auto"
      variant="outlined"
      color="primary"
    ></v-text-field>    
    <v-text-field
      v-model="phone"
      :rules="phoneRules"
      label="Phone number"
      class="mt-4 mb-4"
      required
      density="comfortable"
      hide-details="auto"
      variant="outlined"
      color="primary"
    ></v-text-field>
    <v-text-field
      v-model="address"
      label="Address"
      class="mt-4 mb-4"
      required
      density="comfortable"
      hide-details="auto"
      variant="outlined"
      color="primary"
    ></v-text-field>
      <v-select label="Gender" :items="['male', 'female', 'other']" v-model="gender" variant="outlined">
      </v-select>
    <div class="d-sm-inline-flex align-center mt-2 mb-7 mb-sm-0 font-weight-bold">
      <v-checkbox
        v-model="checkbox"
        :rules="[(v) => !!v || 'You must agree to continue!']"
        label="Agree with?"
        required
        color="primary"
        class="ms-n2"
        hide-details
      ></v-checkbox>
      <a href="#" class="ml-1 text-lightText">Terms and Condition</a>
    </div>
    <v-btn color="secondary" block class="mt-2" variant="flat" size="large" @click="validate()">Sign Up</v-btn>
  </v-form>
  <div class="mt-5 text-right">
    <v-divider />
    <v-btn variant="plain" to="/auth/login" class="mt-2 text-capitalize mr-n2">Already have an account?</v-btn>
  </div>
</template>
<style lang="scss">
.custom-devider {
  border-color: rgba(0, 0, 0, 0.08) !important;
}
.googleBtn {
  border-color: rgba(0, 0, 0, 0.08);
  margin: 30px 0 20px 0;
}
.outlinedInput .v-field {
  border: 1px solid rgba(0, 0, 0, 0.08);
  box-shadow: none;
}
.orbtn {
  padding: 2px 40px;
  border-color: rgba(0, 0, 0, 0.08);
  margin: 20px 15px;
}
.pwdInput {
  position: relative;
  .v-input__append {
    position: absolute;
    right: 10px;
    top: 50%;
    transform: translateY(-50%);
  }
}
</style>
