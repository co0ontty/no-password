import { deriveAuthSecret } from "./crypto";
import type { VaultItem } from "./types";

export type ServerSession = {
  baseUrl: string;
  token: string;
};

export async function registerWithServer(baseUrl: string, email: string, masterPassword: string) {
  const authSecret = await deriveAuthSecret(email, masterPassword);
  const response = await fetch(`${baseUrl}/api/auth/register`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      email,
      authSecret,
      kdf: { name: "PBKDF2-SHA256", iterations: 310000 },
    }),
  });

  if (!response.ok) {
    throw new Error(await errorText(response));
  }

  return response.json() as Promise<{ token: string; profile: { id: string; email: string } }>;
}

export async function loginWithServer(baseUrl: string, email: string, masterPassword: string) {
  const authSecret = await deriveAuthSecret(email, masterPassword);
  const response = await fetch(`${baseUrl}/api/auth/login`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ email, authSecret }),
  });

  if (!response.ok) {
    throw new Error(await errorText(response));
  }

  return response.json() as Promise<{ token: string; profile: { id: string; email: string } }>;
}

export async function pushVault(session: ServerSession, items: VaultItem[]) {
  const response = await fetch(`${session.baseUrl}/api/vault`, {
    method: "PUT",
    headers: {
      authorization: `Bearer ${session.token}`,
      "content-type": "application/json",
    },
    body: JSON.stringify({
      revision: Date.now(),
      items: items.map((item) => ({
        id: item.id,
        kind: item.kind,
        cipher: btoa(JSON.stringify(item)),
        nonce: "local-preview",
        updatedAt: item.updatedAt,
      })),
    }),
  });

  if (!response.ok) {
    throw new Error(await errorText(response));
  }
}

async function errorText(response: Response) {
  try {
    const body = await response.json();
    return body.error ?? response.statusText;
  } catch {
    return response.statusText;
  }
}
