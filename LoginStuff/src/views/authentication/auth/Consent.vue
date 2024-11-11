<script setup lang="ts">
import Logo from '@/layouts/full/logo/LogoDark.vue';
import AuthConsent from '../authForms/AuthConsent.vue';
import { useRouter } from 'vue-router';

const request = useRouter();
const path = request.currentRoute.value.query;

</script>

<template>
  <v-row class="h-screen" no-gutters>
    <!---Left Part-->
    <v-col cols="12" class="d-flex align-center bg-lightprimary">
      <v-container>
        <div class="pa-7 pa-sm-12">
          <v-row justify="center">
            <v-col cols="12" lg="10" xl="8">
              <v-card elevation="0" class="consentBox">
                <v-card variant="outlined">
                  <!-- <v-card-text class="pa-9"> -->
                    <v-card-text class="pa-0">
                    <!---Left Part Logo -->
                    <!---Left Part Logo -->

                    <!---Left Part Form-->
                    <AuthConsent :path="path"/>
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
.consentBox {
  max-width: auto;
  margin: 0 auto;
}
</style>
