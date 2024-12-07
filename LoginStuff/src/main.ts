import { createApp } from 'vue';
import { createPinia } from 'pinia';
import App from './App.vue';
import { router } from './router';
import vuetify from './plugins/vuetify';
import '@/scss/style.scss';
import '@mdi/font/css/materialdesignicons.css';
import { PerfectScrollbarPlugin } from 'vue3-perfect-scrollbar';
import VueApexCharts from 'vue3-apexcharts';
import VueTablerIcons from 'vue-tabler-icons';
import { piniaSessionStorage } from './stores/piniaSessionStorage';
// import vue3GoogleLogin from 'vue3-google-login';

// print
import print from 'vue3-print-nb';
// import { GoogleClientId } from './extensions/IdentityServer';

const app = createApp(App);
//fakeBackend();
// app.use(GoogleSignInPlugin, {
//     clientId: GoogleClientId
// });
const pinia = createPinia();
pinia.use(piniaSessionStorage);

// app.use(vue3GoogleLogin, {
//   clientId: '558160357396-q5qp0ppf4r5svc0g0smshfs8cdcffkm3.apps.googleusercontent.com'
// });
app.use(PerfectScrollbarPlugin);
app.use(pinia);
app.use(router);
app.use(VueTablerIcons);
app.use(print);
app.use(VueApexCharts);
app.use(vuetify).mount('#app');
