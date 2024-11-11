// src/plugins/piniaSessionStorage.js
import type { PiniaPluginContext } from 'pinia';

export function piniaSessionStorage({ store }: PiniaPluginContext) {
  const storedState = sessionStorage.getItem(store.$id);
  if (storedState) {
    store.$patch(JSON.parse(storedState));
  }

  store.$subscribe((mutation, state) => {
    sessionStorage.setItem(store.$id, JSON.stringify(state));
  });
}