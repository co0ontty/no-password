import { toArrayBuffer } from "./crypto";

const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

export type TotpCode = {
  code: string;
  remaining: number;
};

export function extractOtpSecret(value: string): string {
  const trimmed = value.trim();
  if (!trimmed) return "";

  try {
    const url = new URL(trimmed);
    if (url.protocol === "otpauth:") {
      return sanitizeBase32(url.searchParams.get("secret") ?? "");
    }
  } catch {
    // Plain Base32 secrets are expected here.
  }

  return sanitizeBase32(trimmed);
}

export async function generateTotp(value: string, now = Date.now()): Promise<TotpCode | null> {
  const secret = extractOtpSecret(value);
  if (!secret) return null;

  const keyBytes = decodeBase32(secret);
  if (keyBytes.length === 0) return null;

  const step = 30;
  const counter = Math.floor(now / 1000 / step);
  const remaining = step - (Math.floor(now / 1000) % step);
  const counterBytes = new ArrayBuffer(8);
  new DataView(counterBytes).setBigUint64(0, BigInt(counter));

  const key = await crypto.subtle.importKey(
    "raw",
    toArrayBuffer(keyBytes),
    { name: "HMAC", hash: "SHA-1" },
    false,
    ["sign"],
  );
  const hmac = new Uint8Array(await crypto.subtle.sign("HMAC", key, counterBytes));
  const offset = hmac[hmac.length - 1] & 0x0f;
  const binary =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);
  const code = String(binary % 1_000_000).padStart(6, "0");

  return { code, remaining };
}

function sanitizeBase32(value: string): string {
  return value.toUpperCase().replace(/[^A-Z2-7]/g, "");
}

function decodeBase32(value: string): Uint8Array {
  const bits: number[] = [];
  for (const char of value.replace(/=+$/g, "")) {
    const index = BASE32_ALPHABET.indexOf(char);
    if (index === -1) continue;
    for (let bit = 4; bit >= 0; bit -= 1) {
      bits.push((index >> bit) & 1);
    }
  }

  const bytes = [];
  for (let index = 0; index + 8 <= bits.length; index += 8) {
    bytes.push(bits.slice(index, index + 8).reduce((byte, bit) => (byte << 1) | bit, 0));
  }

  return new Uint8Array(bytes);
}
