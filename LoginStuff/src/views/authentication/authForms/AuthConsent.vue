<script setup lang="ts">
import favicon from '@/assets/images/favicon.svg';
import { ref, defineProps } from 'vue';
import type { LocationQuery } from 'vue-router';
import { useAxiosPostWithHeaders } from '@/extensions/RequestUltilities';
import { OauthEndpoint } from '@/stores/Utilities';
//import { Static } from '../IdentityServerInformation';
import { useAuthStore } from '@/stores/auth';
import { Base64ToString } from '@/extensions/RNGCryptoUltilities';
import { router } from '@/router';

const props = defineProps<{
  path: LocationQuery
}>();

const client = "CLIENT";
// const temp = `By continuing, Google will share your name, email address, language preference, and profile picture with IssuerOfClaims.
// See IssuerOfClaims’s Privacy Policy and Terms of Service.You can manage Sign in with Google in your Google Account.`;

function Click(allowAccess: boolean) {
  // console.log(props.path.path);
  // console.log(Base64ToString(props.path.path));
  const useAuth = useAuthStore();
  const promptValue = allowAccess ? 'granted': 'not_allow';

  useAxiosPostWithHeaders(OauthEndpoint.AuthorizeEndpoint, {
    Authorization: `id_token ${useAuth.user}`
  }, `${Base64ToString(props.path.path)}&consent_granted=${promptValue}`, (response) => {
    console.log(response);
    router.push('/close-tab');
  }, undefined, (error) => {
    console.log(error);
    router.push('/close-tab');
  });
}

</script>

<template>
  <div class="d-flex pa-1rem align-center">
    <img :src="favicon" alt="DTBIdentityServer" class="icon-size-px-medium" />
    <span class="ml-2 p-fs-medium text-bold">Sign in with DTB</span>
  </div>
  <v-row>
    <v-col class="d-flex align-center">
      <v-divider class="custom-devider" thickness="2" />
    </v-col>
  </v-row>
  <div class="d-flex pa-1">
    <v-card class="mr-2 border-transparent" variant="outlined">
      <template v-slot:text>
        <p>Sign in to {{ client }}</p>
      </template>
      <!-- TODO: allow users choose between usable accounts which have been logged on local browser or application -->
      <template v-slot:actions>
        <v-btn>
          <img :src="favicon" alt="DTBIdentityServer" class="icon-size-px-small" />
          <span class="ml-2 p-fs-medium text-bold">Account</span>
        </v-btn>
      </template>
    </v-card>
    <v-card variant="outlined" class="ml-2 border-transparent">
      <template v-slot:text>
        <p> By continuing, this application will share your name, email address, language preference,
          and profile picture with {{ client }}.
          See {{ client }}’s Privacy Policy and Terms of Service.</p>
        <!--<p>Bạn có thể quản lý tính năng Đăng nhập bằng {{ServerName}} trong Tài khoản {{ServerName}} của mình.</p> -->
      </template>
      <template v-slot:actions>
        <div class="d-flex">
          <v-btn @click="Click(false)">Cancel</v-btn>
          <v-btn @click="Click(true)">Ok</v-btn>
        </div>
      </template>
    </v-card>
  </div>
</template>

<style lang="scss">
$paddings: (
  "24px": 24px,
  "1rem": 1rem,
  "2rem": 2rem
);
$icon-sizes: (
  "small": 20px,
  "medium": 40px,
  "large": 60px
);

@each $name, $value in $paddings {
  .pa-#{$name} {
    padding: $value;
  }
}

@each $name, $value in $icon-sizes {
  .icon-size-px-#{$name} {
    width: $value;
  }
}

.border-transparent {
  border: transparent;
}

.variant-outlined {
  variant: outlined;
}

.p-fs-medium {
  font-size: medium;
}

.text-bold {
  font-weight: normal;
}
</style>