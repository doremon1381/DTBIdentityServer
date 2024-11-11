// src/stores/counter.js
import { defineStore } from 'pinia';

interface UserInfo{
    userName: string,
    accessToken: string,
    refreshToken: string,
    expiredIn: string
}

export const useUserInfoStore = defineStore('userInfo', {
  state: (): UserInfo => ({
    userName: "",
    accessToken: "",
    refreshToken: "",
    expiredIn: ""
  }),
  actions: { },
});