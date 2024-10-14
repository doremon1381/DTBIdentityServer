import { router } from "@/router";
import { useAuthStore } from "@/stores/auth";
//import { useAuthStore } from "@/stores/auth";
import axios, { AxiosError, type AxiosResponse, type RawAxiosRequestHeaders } from "axios";
//import AxiosResponse from "axios";
import { ref } from "vue";

// authInfo = useAuthStore();
type NX = (value: void) => void;
type HR = (value: AxiosResponse) => void;
type ER = (value: AxiosError) => void
const webServerTestRequest = ref("https://localhost:7209");

function useAxiosGet(uri: string, handleResponse: HR, nextRequest?: NX, errorHandler?: NX)
{
   const data = ref(null);

   axios.get(uri).then(response => {
       //data.value = response.data;
       handleResponse(response);
   }).catch(error => {
       //console.log(error);
       if (errorHandler != undefined)
            errorHandler(error);
        // TODO: if 401, use router to redirect
        if (error.status == 401)
                router.push('/auth/login')
   }).then(()=> {
        if (nextRequest != undefined)
            nextRequest();
   });

   return data;
}

function useAxiosGetWithHeaders(uri: string, headers: RawAxiosRequestHeaders, handleResponse: HR, nextRequest?: NX, errorHandler?: NX)
{
   //const data = ref(null);

   axios.get(uri,{
       headers
   }).then(response => {
       //data.value = response.data;
       handleResponse(response);
   }).catch(error => {
       //console.log(error);
       if (errorHandler != undefined)
            errorHandler(error);
       // TODO: if 401, use router to redirect
       if (error.status == 401)
            router.push('/auth/login')
   }).then(()=> {
    if (nextRequest != undefined)
        nextRequest();
   });

   //return data;
}

function useAxiosGetWithAccessToken(api: string, handleResponse: HR, nextRequest?: NX, errorHandler?: ER)
{
   const data = useAuthStore();

   axios.get(webServerTestRequest.value + api, {
    headers:{
        Authorization: "Bearer " + data.user.access_token
    }
   }).then(response => {
       //data.value = response.data;
       handleResponse(response);
   }).catch(error => {
    if (errorHandler != undefined)
        errorHandler(error);
   // TODO: if 401, use router to redirect
   if (error.status == 401)
        router.push('/auth/login')
   }).then(()=> {
    if (nextRequest != undefined)
        nextRequest();
   });
}

function useAxiosPostWithAccessToken(api: string, requestBody, handleResponse: HR, nextRequest?: NX, errorHandler?: ER)
{
    const data = useAuthStore();

    axios.post(webServerTestRequest.value + api, {
        users: requestBody
    }, {
     headers:{
         Authorization: "Bearer " + data.user.access_token
     }
    }).then(response => {
        //data.value = response.data;
        handleResponse(response);
    }).catch(error => {
     if (errorHandler != undefined)
         errorHandler(error);
    // TODO: if 401, use router to redirect
    if (error.status == 401)
         router.push('/auth/login')
    }).then(()=> {
     if (nextRequest != undefined)
         nextRequest();
    });
}

 export { useAxiosGet, useAxiosGetWithHeaders, useAxiosGetWithAccessToken, useAxiosPostWithAccessToken, webServerTestRequest };
