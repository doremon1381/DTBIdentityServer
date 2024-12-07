import type { LocationQueryValue } from 'vue-router';

function ByteArrayToBase64(byteArray): string {
  return btoa(String.fromCharCode.apply(null, byteArray));
}

function Base64ToString(str: string) : string{
  const temp = atob(str);
  return temp;
}

function ByteArrayToBase64NoPadding(byteArray) {
  let temp = btoa(String.fromCharCode.apply(null, byteArray));
  // convert base64 to base64url
  temp = temp.replace('+', '-');
  temp = temp.replace('/', '_');
  // strips padding
  temp = temp.replace('=', '');

  return temp;
}

function StringUTF8ToByteArray(str: string): Uint8Array {
  return new TextEncoder().encode(str);
}

function GenerateRandomStringWithLength(length: number) {
  const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^*';
  const charactersLength = characters.length;
  let count = 0;
  let temp = '';
  while (count < length) {
    temp += characters[Math.floor(Math.random() * charactersLength)];
    count += 1;
  }

  return temp;
}

export { ByteArrayToBase64, ByteArrayToBase64NoPadding, StringUTF8ToByteArray, GenerateRandomStringWithLength, Base64ToString };
