import { deriveAuthSecret, deriveLegacyAuthSecret } from "./crypto";
import type { LocalVaultBlob } from "./types";

export class ApiRequestError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
    this.name = "ApiRequestError";
  }
}

export type ServerSession = {
  baseUrl: string;
  token: string;
};

export type TlsCertificateConfig = {
  site: string;
  certificatePath: string;
  privateKeyPath: string;
};

export type SavedTlsCertificateConfig = TlsCertificateConfig & {
  updatedAt: number;
};

export type TlsSettingsResponse = {
  current: SavedTlsCertificateConfig | null;
  defaultSite: string;
};

export type TlsTestResponse = {
  ok: boolean;
  testId: string;
  message: string;
};

export type ServerConfigResponse = {
  appName: string;
  publicOrigin: string;
  rpId: string;
  passkeyServerApi: string;
  ownerEmail: string;
};

type VaultEnvelope = {
  id: string;
  kind: string;
  cipher: string;
  nonce: string;
  updatedAt: number;
};

type VaultResponse = {
  revision: number;
  items: VaultEnvelope[];
  updatedAt: number;
};

const VAULT_BLOB_ID = "vault-blob-v1";
const VAULT_BLOB_KIND = "encrypted-vault";
const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

export async function getServerConfig(baseUrl: string) {
  const response = await fetch(`${apiBase(baseUrl)}/api/config`);

  if (!response.ok) {
    throw new ApiRequestError(response.status, await errorText(response));
  }

  return response.json() as Promise<ServerConfigResponse>;
}

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
    throw new ApiRequestError(response.status, await errorText(response));
  }

  return response.json() as Promise<{ token: string; profile: { id: string; email: string } }>;
}

export async function loginWithServer(baseUrl: string, email: string, masterPassword: string) {
  const authSecret = await deriveAuthSecret(email, masterPassword);
  try {
    return await loginWithAuthSecret(baseUrl, email, authSecret);
  } catch (error) {
    if (!(error instanceof ApiRequestError) || error.status !== 401) throw error;
  }

  const legacyAuthSecret = await deriveLegacyAuthSecret(email, masterPassword);
  return loginWithAuthSecret(baseUrl, email, legacyAuthSecret, authSecret);
}

async function loginWithAuthSecret(
  baseUrl: string,
  email: string,
  authSecret: string,
  nextAuthSecret?: string,
) {
  const response = await fetch(`${apiBase(baseUrl)}/api/auth/login`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ email, authSecret, nextAuthSecret }),
  });

  if (!response.ok) {
    throw new ApiRequestError(response.status, await errorText(response));
  }

  return response.json() as Promise<{ token: string; profile: { id: string; email: string } }>;
}

export async function updateAccountEmail(
  session: ServerSession,
  nextEmail: string,
) {
  const response = await fetch(`${apiBase(session.baseUrl)}/api/account/email`, {
    method: "POST",
    headers: {
      ...authHeaders(session),
      "content-type": "application/json",
    },
    body: JSON.stringify({
      email: nextEmail,
    }),
  });

  if (!response.ok) {
    throw new ApiRequestError(response.status, await errorText(response));
  }

  return response.json() as Promise<{ token: string; profile: { id: string; email: string } }>;
}

export async function updateAccountPassword(
  session: ServerSession,
  email: string,
  currentPassword: string,
  nextPassword: string,
) {
  const nextAuthSecret = await deriveAuthSecret(email, nextPassword);
  const currentAuthSecret = await deriveAuthSecret(email, currentPassword);
  try {
    return await updateAccountPasswordWithSecret(session, currentAuthSecret, nextAuthSecret);
  } catch (error) {
    if (!(error instanceof ApiRequestError) || error.status !== 401) throw error;
  }

  const legacyCurrentAuthSecret = await deriveLegacyAuthSecret(email, currentPassword);
  return updateAccountPasswordWithSecret(session, legacyCurrentAuthSecret, nextAuthSecret);
}

async function updateAccountPasswordWithSecret(
  session: ServerSession,
  currentAuthSecret: string,
  nextAuthSecret: string,
) {
  const response = await fetch(`${apiBase(session.baseUrl)}/api/account/password`, {
    method: "POST",
    headers: {
      ...authHeaders(session),
      "content-type": "application/json",
    },
    body: JSON.stringify({
      currentAuthSecret,
      nextAuthSecret,
    }),
  });

  if (!response.ok) {
    throw new ApiRequestError(response.status, await errorText(response));
  }

  return response.json() as Promise<{ token: string; profile: { id: string; email: string } }>;
}

export async function pullVault(session: ServerSession): Promise<{
  revision: number;
  blob: LocalVaultBlob | null;
  updatedAt: number;
}> {
  const response = await fetch(`${apiBase(session.baseUrl)}/api/vault`, {
    headers: authHeaders(session),
  });

  if (!response.ok) {
    throw new ApiRequestError(response.status, await errorText(response));
  }

  const vault = (await response.json()) as VaultResponse;
  return {
    revision: vault.revision,
    blob: decodeVaultBlob(vault.items),
    updatedAt: vault.updatedAt,
  };
}

export async function pushVault(session: ServerSession, blob: LocalVaultBlob, revision = Date.now()) {
  const response = await fetch(`${apiBase(session.baseUrl)}/api/vault`, {
    method: "PUT",
    headers: {
      ...authHeaders(session),
      "content-type": "application/json",
    },
    body: JSON.stringify({
      revision,
      items: [encodeVaultBlob(blob)],
    }),
  });

  if (!response.ok) {
    throw new ApiRequestError(response.status, await errorText(response));
  }

  return response.json() as Promise<VaultResponse>;
}

export async function getTlsSettings(session: ServerSession) {
  const response = await fetch(`${apiBase(session.baseUrl)}/api/admin/tls`, {
    headers: authHeaders(session),
  });

  if (!response.ok) {
    throw new ApiRequestError(response.status, await errorText(response));
  }

  return response.json() as Promise<TlsSettingsResponse>;
}

export async function testTlsSettings(session: ServerSession, config: TlsCertificateConfig) {
  const response = await fetch(`${apiBase(session.baseUrl)}/api/admin/tls/test`, {
    method: "POST",
    headers: {
      ...authHeaders(session),
      "content-type": "application/json",
    },
    body: JSON.stringify(config),
  });

  if (!response.ok) {
    throw new ApiRequestError(response.status, await errorText(response));
  }

  return response.json() as Promise<TlsTestResponse>;
}

export async function saveTlsSettings(
  session: ServerSession,
  config: TlsCertificateConfig & { testId: string },
) {
  const response = await fetch(`${apiBase(session.baseUrl)}/api/admin/tls`, {
    method: "PUT",
    headers: {
      ...authHeaders(session),
      "content-type": "application/json",
    },
    body: JSON.stringify(config),
  });

  if (!response.ok) {
    throw new ApiRequestError(response.status, await errorText(response));
  }

  return response.json() as Promise<{ current: SavedTlsCertificateConfig; reloaded: boolean }>;
}

function authHeaders(session: ServerSession) {
  return {
    authorization: `Bearer ${session.token}`,
  };
}

function apiBase(baseUrl: string) {
  return baseUrl.replace(/\/+$/, "");
}

function encodeVaultBlob(blob: LocalVaultBlob): VaultEnvelope {
  return {
    id: VAULT_BLOB_ID,
    kind: VAULT_BLOB_KIND,
    cipher: encodeJson(blob),
    nonce: blob.iv,
    updatedAt: blob.updatedAt,
  };
}

function decodeVaultBlob(items: VaultEnvelope[]): LocalVaultBlob | null {
  const item = items.find(
    (candidate) => candidate.id === VAULT_BLOB_ID && candidate.kind === VAULT_BLOB_KIND,
  );
  if (!item) return null;
  try {
    return decodeJson<LocalVaultBlob>(item.cipher);
  } catch {
    return null;
  }
}

function encodeJson(value: unknown): string {
  const bytes = textEncoder.encode(JSON.stringify(value));
  let binary = "";
  bytes.forEach((byte) => {
    binary += String.fromCharCode(byte);
  });
  return btoa(binary);
}

function decodeJson<T>(value: string): T {
  const binary = atob(value);
  const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));
  return JSON.parse(textDecoder.decode(bytes)) as T;
}

async function errorText(response: Response) {
  try {
    const body = await response.json();
    return body.error ?? response.statusText;
  } catch {
    return response.statusText;
  }
}
