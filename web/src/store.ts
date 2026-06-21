import { bytesToBase64, decryptJson, deriveVaultKey, encryptJson, KDF_ITERATIONS, randomBytes } from "./crypto";
import type { LocalPasskey, LocalVaultBlob, VaultItem, VaultSession } from "./types";

const VAULT_KEY = "np.localVault.v1";
const PASSKEY_KEY = "np.localPasskeys.v1";

export function readVaultBlob(): LocalVaultBlob | null {
  const raw = localStorage.getItem(VAULT_KEY);
  if (!raw) return null;
  try {
    return JSON.parse(raw) as LocalVaultBlob;
  } catch {
    return null;
  }
}

export function hasVault(): boolean {
  return readVaultBlob() !== null;
}

export async function createVault(email: string, masterPassword: string): Promise<{
  session: VaultSession;
  items: VaultItem[];
}> {
  const saltBytes = randomBytes(16);
  const salt = bytesToBase64(saltBytes);
  const key = await deriveVaultKey(masterPassword, saltBytes);
  const session: VaultSession = {
    email: email.trim().toLowerCase(),
    key,
    salt,
    kdf: {
      name: "PBKDF2-SHA256",
      iterations: KDF_ITERATIONS,
    },
  };

  const items = seedItems();
  await persistVault(session, items);
  return { session, items };
}

export async function unlockVault(masterPassword: string): Promise<{
  session: VaultSession;
  items: VaultItem[];
}> {
  const blob = readVaultBlob();
  if (!blob) {
    throw new Error("No local vault found");
  }
  const key = await deriveVaultKey(masterPassword, Uint8Array.from(atob(blob.salt), (char) => char.charCodeAt(0)));
  const items = await decryptJson<VaultItem[]>(key, blob.iv, blob.ciphertext);
  return {
    session: {
      email: blob.email,
      key,
      salt: blob.salt,
      kdf: blob.kdf,
    },
    items,
  };
}

export async function persistVault(session: VaultSession, items: VaultItem[]): Promise<void> {
  const encrypted = await encryptJson(session.key, items);
  const blob: LocalVaultBlob = {
    version: 1,
    email: session.email,
    salt: session.salt,
    iv: encrypted.iv,
    ciphertext: encrypted.ciphertext,
    kdf: session.kdf,
    updatedAt: Date.now(),
  };
  localStorage.setItem(VAULT_KEY, JSON.stringify(blob));
}

export function clearVault(): void {
  localStorage.removeItem(VAULT_KEY);
  localStorage.removeItem(PASSKEY_KEY);
}

export function readPasskeys(): LocalPasskey[] {
  const raw = localStorage.getItem(PASSKEY_KEY);
  if (!raw) return [];
  try {
    return JSON.parse(raw) as LocalPasskey[];
  } catch {
    return [];
  }
}

export function savePasskey(passkey: LocalPasskey): LocalPasskey[] {
  const next = [passkey, ...readPasskeys().filter((item) => item.id !== passkey.id)];
  localStorage.setItem(PASSKEY_KEY, JSON.stringify(next));
  return next;
}

export function removePasskey(id: string): LocalPasskey[] {
  const next = readPasskeys().filter((item) => item.id !== id);
  localStorage.setItem(PASSKEY_KEY, JSON.stringify(next));
  return next;
}

function seedItems(): VaultItem[] {
  const now = Date.now();
  return [
    {
      id: crypto.randomUUID(),
      kind: "login",
      title: "GitHub",
      username: "alex@example.com",
      password: "Z8q!uQ4p@qN7vL2s",
      url: "https://github.com",
      notes: "Recovery codes stored in secure note.",
      tags: ["work", "dev"],
      favorite: true,
      updatedAt: now,
    },
    {
      id: crypto.randomUUID(),
      kind: "login",
      title: "Stripe",
      username: "billing@example.com",
      password: "K9#tWm6!cQ2xRz8",
      url: "https://dashboard.stripe.com",
      notes: "Shared with finance vault later.",
      tags: ["finance"],
      favorite: false,
      updatedAt: now - 86_400_000,
    },
    {
      id: crypto.randomUUID(),
      kind: "secure-note",
      title: "Server Recovery",
      username: "",
      password: "",
      url: "",
      notes: "Store emergency deployment notes here after replacing this sample.",
      tags: ["infra"],
      favorite: false,
      updatedAt: now - 172_800_000,
    },
  ];
}

