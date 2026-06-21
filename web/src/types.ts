export type VaultItemKind = "login" | "secure-note" | "card" | "passkey";

export type VaultItem = {
  id: string;
  kind: VaultItemKind;
  title: string;
  username: string;
  password: string;
  url: string;
  notes: string;
  tags: string[];
  favorite: boolean;
  updatedAt: number;
};

export type LocalVaultBlob = {
  version: 1;
  email: string;
  salt: string;
  iv: string;
  ciphertext: string;
  kdf: {
    name: "PBKDF2-SHA256";
    iterations: number;
  };
  updatedAt: number;
};

export type VaultSession = {
  email: string;
  key: CryptoKey;
  salt: string;
  kdf: LocalVaultBlob["kdf"];
};

export type LocalPasskey = {
  id: string;
  rawId: string;
  rpId: string;
  email: string;
  createdAt: number;
};

