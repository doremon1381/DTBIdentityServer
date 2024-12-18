import { defineStore } from "pinia";

interface AuthenticationFlow{
    flow: string,
    path: string
}

export const useAuthenticationParametersStore = defineStore<'authenticationFlow', AuthenticationFlow>({
    id: 'authenticationFlow',
    state: () : AuthenticationFlow => ({
        flow: "",
        path: ""
    })
});