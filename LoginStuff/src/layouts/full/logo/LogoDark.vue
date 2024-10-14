<template>
  <div class="logo">
    <RouterLink to="/" style="display:block; margin: auto; text-decoration: none; align-items: center; text-align: center;">
      <svg width="92" height="40" viewBox="0 0 92 32" fill="none" xmlns="http://www.w3.org/2000/svg">        
        <image href="./images/1181213675304357.jpg" width="100%" height="100%"/>
      </svg>
      <h4 class="text-disabled text-h4 mt-3">Doraemon's Project</h4>
    </RouterLink>
  </div>
</template>
<script setup lang="ts">
import { ref } from 'vue';
import { RouterLink } from 'vue-router';
const primary = ref('rgb(var(--v-theme-primary))');
const secondary = ref('rgb(var(--v-theme-secondary))');
</script>
