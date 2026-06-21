import { base64UrlToBytes, bytesToBase64Url, randomBytes, toArrayBuffer } from "./crypto";
import type { LocalPasskey } from "./types";

export async function getPasskeySupport(): Promise<{
  supported: boolean;
  secureContext: boolean;
  platformAuthenticator: boolean;
}> {
  const secureContext = window.isSecureContext;
  const supported = "PublicKeyCredential" in window && "credentials" in navigator;
  const platformAuthenticator =
    supported && "isUserVerifyingPlatformAuthenticatorAvailable" in PublicKeyCredential
      ? await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()
      : false;

  return {
    supported,
    secureContext,
    platformAuthenticator,
  };
}

export async function registerLocalPasskey(email: string): Promise<LocalPasskey> {
  if (!window.isSecureContext || !("credentials" in navigator)) {
    throw new Error("Passkeys require a secure browser context");
  }

  const challenge = randomBytes(32);
  const userId = randomBytes(16);
  const rpId = location.hostname;

  const credential = await navigator.credentials.create({
    publicKey: {
      challenge: toArrayBuffer(challenge),
      rp: {
        id: rpId,
        name: "NoPassword",
      },
      user: {
        id: toArrayBuffer(userId),
        name: email,
        displayName: email,
      },
      pubKeyCredParams: [
        { type: "public-key", alg: -7 },
        { type: "public-key", alg: -257 },
      ],
      authenticatorSelection: {
        residentKey: "required",
        userVerification: "required",
      },
      timeout: 60_000,
      attestation: "none",
    },
  });

  if (!credential || !(credential instanceof PublicKeyCredential)) {
    throw new Error("Passkey registration was cancelled");
  }

  return {
    id: credential.id,
    rawId: bytesToBase64Url(new Uint8Array(credential.rawId)),
    rpId,
    email,
    createdAt: Date.now(),
  };
}

export async function verifyLocalPasskey(passkey: LocalPasskey): Promise<boolean> {
  const assertion = await navigator.credentials.get({
    publicKey: {
      challenge: toArrayBuffer(randomBytes(32)),
      rpId: passkey.rpId,
      allowCredentials: [
        {
          type: "public-key",
          id: toArrayBuffer(base64UrlToBytes(passkey.rawId)),
        },
      ],
      userVerification: "required",
      timeout: 60_000,
    },
  });

  return assertion instanceof PublicKeyCredential;
}
