const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

export const KDF_ITERATIONS = 310_000;

export function randomBytes(length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytes;
}

export function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const buffer = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(buffer).set(bytes);
  return buffer;
}

export function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  bytes.forEach((byte) => {
    binary += String.fromCharCode(byte);
  });
  return btoa(binary);
}

export function base64ToBytes(value: string): Uint8Array {
  const binary = atob(value);
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

export function bytesToBase64Url(bytes: Uint8Array): string {
  return bytesToBase64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

export function base64UrlToBytes(value: string): Uint8Array {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
  return base64ToBytes(padded);
}

export async function deriveVaultKey(
  masterPassword: string,
  salt: Uint8Array,
  extractable = false,
): Promise<CryptoKey> {
  const material = await crypto.subtle.importKey(
    "raw",
    textEncoder.encode(masterPassword),
    "PBKDF2",
    false,
    ["deriveKey"],
  );

  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: toArrayBuffer(salt),
      iterations: KDF_ITERATIONS,
      hash: "SHA-256",
    },
    material,
    {
      name: "AES-GCM",
      length: 256,
    },
    extractable,
    ["encrypt", "decrypt"],
  );
}

export async function exportVaultKey(key: CryptoKey): Promise<string> {
  const raw = await crypto.subtle.exportKey("raw", key);
  return bytesToBase64(new Uint8Array(raw));
}

export async function importVaultKey(value: string): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "raw",
    toArrayBuffer(base64ToBytes(value)),
    {
      name: "AES-GCM",
      length: 256,
    },
    true,
    ["encrypt", "decrypt"],
  );
}

export async function deriveAuthSecret(_email: string, masterPassword: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    textEncoder.encode(`no-password-auth-v2:${masterPassword}`),
  );
  return bytesToBase64Url(new Uint8Array(digest));
}

export async function deriveLegacyAuthSecret(email: string, masterPassword: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    textEncoder.encode(`no-password-auth-v1:${email.toLowerCase()}:${masterPassword}`),
  );
  return bytesToBase64Url(new Uint8Array(digest));
}

export async function encryptJson<T>(key: CryptoKey, value: T): Promise<{ iv: string; ciphertext: string }> {
  const iv = randomBytes(12);
  const data = textEncoder.encode(JSON.stringify(value));
  const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv: toArrayBuffer(iv) }, key, data);
  return {
    iv: bytesToBase64(iv),
    ciphertext: bytesToBase64(new Uint8Array(encrypted)),
  };
}

export async function decryptJson<T>(key: CryptoKey, iv: string, ciphertext: string): Promise<T> {
  const decrypted = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: toArrayBuffer(base64ToBytes(iv)) },
    key,
    toArrayBuffer(base64ToBytes(ciphertext)),
  );
  return JSON.parse(textDecoder.decode(decrypted)) as T;
}

export function generatePassword(length = 24): string {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*?";
  const bytes = randomBytes(length);
  return Array.from(bytes, (byte) => alphabet[byte % alphabet.length]).join("");
}
