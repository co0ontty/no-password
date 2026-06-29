import { FormEvent, useEffect, useMemo, useState } from "react";
import {
  AtSign,
  Check,
  Copy,
  CreditCard,
  Database,
  Download,
  Eye,
  EyeOff,
  Fingerprint,
  Globe2,
  KeyRound,
  Lock,
  MonitorSmartphone,
  PlugZap,
  Plus,
  Puzzle,
  RefreshCcw,
  Search,
  Server,
  Settings,
  ShieldCheck,
  Sparkles,
  Star,
  Terminal,
  Trash2,
  Wand2,
  X,
} from "lucide-react";
import {
  ApiRequestError,
  getServerConfig,
  getTlsSettings,
  loginWithServer,
  pullVault,
  pushVault,
  registerWithServer,
  saveTlsSettings,
  testTlsSettings,
  updateAccountEmail as updateServerAccountEmail,
  updateAccountPassword as updateServerAccountPassword,
  type ServerSession,
  type TlsCertificateConfig,
} from "./api";
import { exportVaultKey, generatePassword, importVaultKey } from "./crypto";
import { getBrowserMessages } from "./i18n";
import { getPasskeySupport, registerLocalPasskey, verifyLocalPasskey } from "./passkeys";
import {
  changeVaultPassword,
  clearVault,
  createVault,
  createVaultFromItems,
  hasVault,
  persistVault,
  readVaultBlob,
  readPasskeys,
  renamePasskeyEmail,
  removePasskey,
  savePasskey,
  unlockVault,
  unlockVaultBlob,
  unlockVaultBlobWithKey,
  type VaultUnlockResult,
} from "./store";
import { generateTotp } from "./totp";
import type { LocalPasskey, VaultItem, VaultItemKind, VaultSession } from "./types";

type NavView = "vault" | "passkeys" | "settings";
type Category = "all" | VaultItemKind | "favorites" | "otp";
type AuthUnlockResult = VaultUnlockResult & {
  serverSession: ServerSession | null;
};
type CachedUnlockedSession = {
  version: 1;
  baseUrl: string;
  email: string;
  vaultKey: string;
  serverSession: ServerSession | null;
  savedAt: number;
  resumeBlocked?: boolean;
};

const DEFAULT_VAULT_EMAIL = "owner@nopassword.local";
const DOCKER_RESET_COMMAND =
  "docker compose exec nopassword /app/nopassword-server reset-owner-password";
const UNLOCKED_SESSION_KEY = "np.unlockedSession.v1";
const BROWSER_EXTENSION_DOWNLOAD_URL = "/downloads/no-password-browser-extension.zip";
const BROWSER_EXTENSION_FILE_NAME = "no-password-browser-extension.zip";

const categoryIds: Category[] = ["all", "favorites", "login", "card", "otp", "secure-note", "passkey"];

function suggestedTlsSite(defaultSite: string) {
  const trimmed = defaultSite.trim();
  const candidate = /^[a-z][a-z\d+.-]*:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
  try {
    const url = new URL(candidate);
    if (url.hostname) {
      url.protocol = "https:";
      return url.toString().replace(/\/$/, "");
    }
  } catch {
    // Fall through to the current browser host.
  }
  const port = window.location.port ? `:${window.location.port}` : "";
  return `https://${window.location.hostname || "localhost"}${port}`;
}

export function App() {
  const text = useMemo(() => getBrowserMessages(), []);
  const [localVaultReady, setLocalVaultReady] = useState(hasVault);
  const [loginPassword, setLoginPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [resetPasswordModalOpen, setResetPasswordModalOpen] = useState(false);
  const [authBusy, setAuthBusy] = useState(false);
  const [authError, setAuthError] = useState("");
  const [resumeChecked, setResumeChecked] = useState(false);
  const [session, setSession] = useState<VaultSession | null>(null);
  const [items, setItems] = useState<VaultItem[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [category, setCategory] = useState<Category>("all");
  const [view, setView] = useState<NavView>("vault");
  const [passkeys, setPasskeys] = useState<LocalPasskey[]>(readPasskeys());
  const [passkeyStatus, setPasskeyStatus] = useState(text.status.checking);
  const [secureCopy, setSecureCopy] = useState("");
  const [otpCode, setOtpCode] = useState<{ code: string; remaining: number } | null>(null);
  const [serverBaseUrl, setServerBaseUrl] = useState(() => window.location.origin);
  const [serverPassword, setServerPassword] = useState("");
  const [serverSession, setServerSession] = useState<ServerSession | null>(null);
  const [serverStatus, setServerStatus] = useState(text.status.notConnected);
  const [serverConnectBusy, setServerConnectBusy] = useState(false);
  const [accountEmail, setAccountEmail] = useState("");
  const [accountEmailStatus, setAccountEmailStatus] = useState("");
  const [accountEmailBusy, setAccountEmailBusy] = useState(false);
  const [currentMasterPassword, setCurrentMasterPassword] = useState("");
  const [nextMasterPassword, setNextMasterPassword] = useState("");
  const [confirmMasterPassword, setConfirmMasterPassword] = useState("");
  const [passwordChangeStatus, setPasswordChangeStatus] = useState("");
  const [passwordChangeBusy, setPasswordChangeBusy] = useState(false);
  const [tlsSite, setTlsSite] = useState("");
  const [tlsCertificatePath, setTlsCertificatePath] = useState("");
  const [tlsPrivateKeyPath, setTlsPrivateKeyPath] = useState("");
  const [tlsTestId, setTlsTestId] = useState("");
  const [tlsStatus, setTlsStatus] = useState(text.status.notTested);
  const [tlsBusy, setTlsBusy] = useState(false);

  useEffect(() => {
    document.documentElement.lang = text.locale;
    document.title = text.documentTitle;
  }, [text]);

  useEffect(() => {
    void getPasskeySupport().then((support) => {
      if (!support.supported) setPasskeyStatus(text.status.unavailable);
      else if (!support.secureContext) setPasskeyStatus(text.status.needsHttps);
      else if (!support.platformAuthenticator) setPasskeyStatus(text.status.externalKeyReady);
      else setPasskeyStatus(text.status.ready);
    });
  }, [text]);

  useEffect(() => {
    if (!resetPasswordModalOpen) return;
    const closeOnEscape = (event: KeyboardEvent) => {
      if (event.key === "Escape") setResetPasswordModalOpen(false);
    };
    window.addEventListener("keydown", closeOnEscape);
    return () => window.removeEventListener("keydown", closeOnEscape);
  }, [resetPasswordModalOpen]);

  useEffect(() => {
    if (!session) return;
    const handle = window.setTimeout(() => {
      void persistVault(session, items).then((blob) => {
        if (!serverSession) return;
        void pushVault(serverSession, blob).catch((error) => {
          if (handleUnauthorizedSession(error)) return;
          setServerStatus(error instanceof Error ? error.message : text.status.connectionFailed);
        });
      });
    }, 200);
    return () => window.clearTimeout(handle);
  }, [items, serverSession, session, text.status.connectionFailed]);

  useEffect(() => {
    if (!session || !serverSession) return;
    let cancelled = false;
    const validateServerSession = async () => {
      try {
        await pullVault(serverSession);
        if (!cancelled) setServerStatus(text.status.connected);
      } catch (error) {
        if (cancelled) return;
        if (handleUnauthorizedSession(error)) return;
        setServerStatus(error instanceof Error ? error.message : text.status.connectionFailed);
      }
    };
    const interval = window.setInterval(validateServerSession, 15_000);
    window.addEventListener("focus", validateServerSession);
    return () => {
      cancelled = true;
      window.clearInterval(interval);
      window.removeEventListener("focus", validateServerSession);
    };
  }, [serverSession, session, text.status.connected, text.status.connectionFailed]);

  useEffect(() => {
    let cancelled = false;
    void restoreUnlockedSession().then((restored) => {
      if (cancelled || !restored) return;
      setSession(restored.session);
      setItems(restored.items);
      setSelectedId(restored.items[0]?.id ?? null);
      setLocalVaultReady(true);
      setServerSession(restored.serverSession);
      setServerStatus(restored.serverSession ? text.status.connected : text.status.notConnected);
    }).finally(() => {
      if (!cancelled) setResumeChecked(true);
    });
    return () => {
      cancelled = true;
    };
  }, [text.status.connected, text.status.notConnected]);

  useEffect(() => {
    setAccountEmail(session?.email ?? "");
    if (!session) setAccountEmailStatus("");
  }, [session?.email]);

  const filteredItems = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return items.filter((item) => {
      const categoryMatch =
        category === "all" ||
        (category === "favorites" && item.favorite) ||
        (category === "otp" && Boolean(item.otpSecret)) ||
        item.kind === category;
      const textMatch =
        !needle ||
        [item.title, item.username, item.url, item.notes, item.otpSecret ?? "", ...item.tags]
          .join(" ")
          .toLowerCase()
          .includes(needle);
      return categoryMatch && textMatch;
    });
  }, [category, items, query]);

  const categoryCounts = useMemo<Record<Category, number>>(() => {
    const counts: Record<Category, number> = {
      all: items.length,
      favorites: 0,
      login: 0,
      card: 0,
      otp: 0,
      "secure-note": 0,
      passkey: 0,
    };
    for (const item of items) {
      counts[item.kind] += 1;
      if (item.favorite) counts.favorites += 1;
      if (item.otpSecret) counts.otp += 1;
    }
    return counts;
  }, [items]);

  const activeCategoryLabel = text.categories[category];

  useEffect(() => {
    if (!session || view !== "vault") return;
    if (filteredItems.length === 0) {
      if (selectedId !== null) setSelectedId(null);
      return;
    }
    if (!selectedId || !filteredItems.some((item) => item.id === selectedId)) {
      setSelectedId(filteredItems[0].id);
    }
  }, [filteredItems, selectedId, session, view]);

  const selected = useMemo(
    () => (selectedId ? items.find((item) => item.id === selectedId) ?? null : null),
    [items, selectedId],
  );

  useEffect(() => {
    let cancelled = false;
    const updateOtp = async () => {
      if (!selected?.otpSecret) {
        setOtpCode(null);
        return;
      }
      const next = await generateTotp(selected.otpSecret).catch(() => null);
      if (!cancelled) setOtpCode(next);
    };
    void updateOtp();
    const handle = window.setInterval(updateOtp, 1000);
    return () => {
      cancelled = true;
      window.clearInterval(handle);
    };
  }, [selected?.id, selected?.otpSecret]);

  const connectionStatus = useMemo(() => {
    const host = window.location.hostname;
    const isLocalHost = host === "localhost" || host === "127.0.0.1" || host === "::1";
    if (window.location.protocol === "https:") return { tone: "secure", label: text.status.trustedHttps };
    if (isLocalHost) return { tone: "warning", label: text.status.localHttp };
    return { tone: "danger", label: text.status.insecureHttp };
  }, [text]);

  const otpItemCount = categoryCounts.otp;
  const authPasswordAutocomplete = localVaultReady ? "current-password" : "new-password";
  const authSubmitLabel = text.auth.signIn;

  async function handleAuth(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (authBusy) return;
    setAuthError("");
    setAuthBusy(true);
    try {
      const next = await openServerVault(loginPassword);
      setSession(next.session);
      setItems(next.items);
      setSelectedId(next.items[0]?.id ?? null);
      setLocalVaultReady(true);
      setServerSession(next.serverSession);
      setServerStatus(next.serverSession ? text.status.connected : text.status.notConnected);
      setResetPasswordModalOpen(false);
      setLoginPassword("");
      await rememberUnlockedSession(next.session, next.serverSession);
    } catch {
      setAuthError(text.auth.loginFailed);
    } finally {
      setAuthBusy(false);
    }
  }

  async function openServerVault(password: string): Promise<AuthUnlockResult> {
    const baseUrl = window.location.origin;
    const loginEmail = await resolveOwnerEmail(baseUrl);
    const auth = await loginWithServer(baseUrl, loginEmail, password).catch(async () => {
      return registerWithServer(baseUrl, loginEmail, password);
    });
    const nextServerSession = { baseUrl, token: auth.token };
    setServerSession(nextServerSession);
    setServerStatus(text.status.connected);
    const remote = await pullVault(nextServerSession);
    if (remote.blob) {
      try {
        const unlocked = await unlockVaultBlob(remote.blob, password);
        return { ...unlocked, serverSession: nextServerSession };
      } catch {
        const cachedRemote = await unlockBlobWithCachedVaultKey(remote.blob);
        if (cachedRemote) {
          return reencryptVaultForLoginPassword(nextServerSession, cachedRemote, password);
        }
      }
      return createServerVault(nextServerSession, password);
    }

    const local = await unlockLocalVaultWithLoginPassword(password);
    if (local) {
      await pushVault(nextServerSession, local.blob);
      return { ...local, serverSession: nextServerSession };
    }
    const cachedLocal = await unlockLocalVaultWithCachedVaultKey();
    if (cachedLocal) {
      return reencryptVaultForLoginPassword(nextServerSession, cachedLocal, password);
    }
    return createServerVault(nextServerSession, password, loginEmail);
  }

  async function resolveOwnerEmail(baseUrl: string) {
    const localEmail = readVaultBlob()?.email;
    try {
      const config = await getServerConfig(baseUrl);
      return config.ownerEmail || localEmail || DEFAULT_VAULT_EMAIL;
    } catch {
      return localEmail || DEFAULT_VAULT_EMAIL;
    }
  }

  async function createServerVault(
    nextServerSession: ServerSession,
    password: string,
    email = DEFAULT_VAULT_EMAIL,
  ): Promise<AuthUnlockResult> {
    const created = await createVault(email, password);
    await pushVault(nextServerSession, created.blob);
    return { ...created, serverSession: nextServerSession };
  }

  async function reencryptVaultForLoginPassword(
    nextServerSession: ServerSession,
    unlocked: VaultUnlockResult,
    password: string,
  ): Promise<AuthUnlockResult> {
    const encrypted = await createVaultFromItems(unlocked.session.email, password, unlocked.items);
    await pushVault(nextServerSession, encrypted.blob);
    return { ...encrypted, serverSession: nextServerSession };
  }

  async function unlockLocalVaultWithLoginPassword(password: string): Promise<VaultUnlockResult | null> {
    if (!localVaultReady) return null;
    return unlockVault(password).catch(() => null);
  }

  async function unlockLocalVaultWithCachedVaultKey(): Promise<VaultUnlockResult | null> {
    const blob = readVaultBlob();
    if (!blob) return null;
    return unlockBlobWithCachedVaultKey(blob);
  }

  async function unlockBlobWithCachedVaultKey(blob: ReturnType<typeof readVaultBlob>): Promise<VaultUnlockResult | null> {
    const cached = readCachedUnlockedSession();
    if (!cached || !blob || cached.email !== blob.email) return null;
    try {
      const key = await importVaultKey(cached.vaultKey);
      return await unlockVaultBlobWithKey(blob, key);
    } catch {
      return null;
    }
  }

  async function rememberUnlockedSession(
    nextSession: VaultSession,
    nextServerSession: ServerSession | null,
  ) {
    try {
      const cached: CachedUnlockedSession = {
        version: 1,
        baseUrl: window.location.origin,
        email: nextSession.email,
        vaultKey: await exportVaultKey(nextSession.key),
        serverSession: nextServerSession,
        savedAt: Date.now(),
        resumeBlocked: false,
      };
      sessionStorage.setItem(UNLOCKED_SESSION_KEY, JSON.stringify(cached));
    } catch {
      // Refresh persistence is a convenience; failed storage should not block unlocking.
    }
  }

  function forgetUnlockedSession() {
    try {
      sessionStorage.removeItem(UNLOCKED_SESSION_KEY);
    } catch {
      // Ignore unavailable storage.
    }
  }

  function forgetCachedServerSession() {
    const cached = readCachedUnlockedSession();
    if (!cached) {
      forgetUnlockedSession();
      return;
    }
    try {
      sessionStorage.setItem(
        UNLOCKED_SESSION_KEY,
        JSON.stringify({
          ...cached,
          serverSession: null,
          savedAt: Date.now(),
          resumeBlocked: true,
        } satisfies CachedUnlockedSession),
      );
    } catch {
      forgetUnlockedSession();
    }
  }

  function readCachedUnlockedSession(): CachedUnlockedSession | null {
    try {
      const raw = sessionStorage.getItem(UNLOCKED_SESSION_KEY);
      if (!raw) return null;
      const cached = JSON.parse(raw) as Partial<CachedUnlockedSession>;
      if (
        cached.version !== 1 ||
        cached.baseUrl !== window.location.origin ||
        !cached.email ||
        !cached.vaultKey
      ) {
        return null;
      }
      return {
        version: 1,
        baseUrl: cached.baseUrl,
        email: cached.email,
        vaultKey: cached.vaultKey,
        serverSession: cached.serverSession?.baseUrl === window.location.origin ? cached.serverSession : null,
        savedAt: typeof cached.savedAt === "number" ? cached.savedAt : 0,
        resumeBlocked: cached.resumeBlocked === true,
      };
    } catch {
      return null;
    }
  }

  async function restoreUnlockedSession(): Promise<AuthUnlockResult | null> {
    const cached = readCachedUnlockedSession();
    const blob = readVaultBlob();
    if (!cached || !blob || cached.email !== blob.email) {
      forgetUnlockedSession();
      return null;
    }
    if (cached.resumeBlocked || !cached.serverSession) return null;

    try {
      const key = await importVaultKey(cached.vaultKey);
      let restored = await unlockVaultBlobWithKey(blob, key);

      try {
        const remote = await pullVault(cached.serverSession);
        if (remote.blob && remote.blob.updatedAt > restored.blob.updatedAt) {
          restored = await unlockVaultBlobWithKey(remote.blob, key);
        }
      } catch (error) {
        if (isUnauthorizedError(error)) forgetCachedServerSession();
        return null;
      }

      await rememberUnlockedSession(restored.session, cached.serverSession);
      return { ...restored, serverSession: cached.serverSession };
    } catch {
      forgetUnlockedSession();
      return null;
    }
  }

  function isUnauthorizedError(error: unknown) {
    return error instanceof ApiRequestError && error.status === 401;
  }

  function handleUnauthorizedSession(error: unknown) {
    if (!isUnauthorizedError(error)) return false;
    clearLoginState(text.auth.loginExpired);
    return true;
  }

  function clearLoginState(message = "") {
    forgetCachedServerSession();
    setSession(null);
    setItems([]);
    setSelectedId(null);
    setServerSession(null);
    setServerStatus(text.status.notConnected);
    setAuthError(message);
  }

  async function syncVaultWithServer(
    nextServerSession: ServerSession,
    local: VaultUnlockResult,
    masterPassword: string,
  ): Promise<VaultUnlockResult> {
    const remote = await pullVault(nextServerSession);
    if (remote.blob && remote.blob.updatedAt > local.blob.updatedAt) {
      try {
        return await unlockVaultBlob(remote.blob, masterPassword);
      } catch {
        try {
          const unlocked = await unlockVaultBlobWithKey(remote.blob, local.session.key);
          return reencryptVaultForLoginPassword(nextServerSession, unlocked, masterPassword);
        } catch {
          return createServerVault(nextServerSession, masterPassword, local.session.email);
        }
      }
    }
    const encrypted = await createVaultFromItems(local.session.email, masterPassword, local.items);
    if (!remote.blob || local.blob.updatedAt > remote.blob.updatedAt) {
      await pushVault(nextServerSession, encrypted.blob);
    }
    return encrypted;
  }

  function addItem(kind: VaultItemKind = "login") {
    const next: VaultItem = {
      id: crypto.randomUUID(),
      kind,
      title:
        kind === "secure-note"
          ? text.newItems.secureNote
          : kind === "passkey"
            ? text.newItems.passkey
            : kind === "card"
              ? text.newItems.card
              : text.newItems.login,
      username: "",
      password: kind === "login" ? generatePassword() : "",
      otpSecret: "",
      url: "",
      notes: "",
      tags: [],
      favorite: false,
      updatedAt: Date.now(),
    };
    setItems((current) => [next, ...current]);
    setSelectedId(next.id);
    setView("vault");
  }

  function updateSelected(patch: Partial<VaultItem>) {
    if (!selected) return;
    setItems((current) =>
      current.map((item) =>
        item.id === selected.id ? { ...item, ...patch, updatedAt: Date.now() } : item,
      ),
    );
  }

  function deleteSelected() {
    if (!selected) return;
    if (!window.confirm(text.confirmations.deleteItem(selected.title))) return;
    const next = items.filter((item) => item.id !== selected.id);
    setItems(next);
    setSelectedId(next[0]?.id ?? null);
  }

  function resetLocalVault() {
    if (!window.confirm(text.confirmations.resetVault)) return;
    forgetUnlockedSession();
    clearVault();
    location.reload();
  }

  async function copyValue(value: string, label: string) {
    try {
      await navigator.clipboard.writeText(value);
    } catch {
      const textarea = document.createElement("textarea");
      textarea.value = value;
      textarea.setAttribute("readonly", "");
      textarea.style.position = "fixed";
      textarea.style.opacity = "0";
      document.body.append(textarea);
      textarea.select();
      document.execCommand("copy");
      textarea.remove();
    }
    setSecureCopy(label);
    window.setTimeout(() => setSecureCopy(""), 1400);
  }

  async function addPasskey() {
    if (!session) return;
    try {
      const passkey = await registerLocalPasskey(session.email);
      setPasskeys(savePasskey(passkey));
      setPasskeyStatus(text.status.linked);
    } catch {
      setPasskeyStatus(text.status.cancelled);
    }
  }

  async function testPasskey(passkey: LocalPasskey) {
    try {
      const verified = await verifyLocalPasskey(passkey);
      setPasskeyStatus(verified ? text.status.verified : text.status.notVerified);
    } catch {
      setPasskeyStatus(text.status.cancelled);
    }
  }

  async function changeAccountEmail() {
    if (!session || accountEmailBusy) return;
    const nextEmail = accountEmail.trim().toLowerCase();
    const currentEmail = session.email.trim().toLowerCase();
    setAccountEmailStatus("");
    if (!serverSession) {
      setAccountEmailStatus(text.status.connectServerFirst);
      return;
    }
    if (nextEmail.length < 3 || !nextEmail.includes("@")) {
      setAccountEmailStatus(text.status.accountEmailInvalid);
      return;
    }
    if (nextEmail === currentEmail) {
      setAccountEmailStatus(text.status.accountEmailUnchanged);
      return;
    }

    setAccountEmailBusy(true);
    setAccountEmailStatus(text.status.saving);
    try {
      const auth = await updateServerAccountEmail(serverSession, nextEmail);
      const normalizedEmail = auth.profile.email;
      const nextServerSession: ServerSession = { baseUrl: serverSession.baseUrl, token: auth.token };
      const nextVaultSession: VaultSession = { ...session, email: normalizedEmail };
      const blob = await persistVault(nextVaultSession, items);

      setSession(nextVaultSession);
      setServerSession(nextServerSession);
      setServerStatus(text.status.connected);
      setPasskeys(renamePasskeyEmail(currentEmail, normalizedEmail));
      await rememberUnlockedSession(nextVaultSession, nextServerSession);
      setAccountEmail(normalizedEmail);

      try {
        await pushVault(nextServerSession, blob);
      } catch (error) {
        setServerStatus(error instanceof Error ? error.message : text.status.connectionFailed);
      }

      setAccountEmailStatus(text.status.accountEmailChanged);
    } catch (error) {
      setAccountEmailStatus(error instanceof Error ? error.message : text.status.accountEmailChangeFailed);
    } finally {
      setAccountEmailBusy(false);
    }
  }

  async function updateMasterPassword() {
    if (!session || passwordChangeBusy) return;
    setPasswordChangeStatus("");
    if (nextMasterPassword.length < 8) {
      setPasswordChangeStatus(text.status.passwordTooShort);
      return;
    }
    if (nextMasterPassword !== confirmMasterPassword) {
      setPasswordChangeStatus(text.status.passwordMismatch);
      return;
    }
    if (currentMasterPassword === nextMasterPassword) {
      setPasswordChangeStatus(text.status.passwordUnchanged);
      return;
    }

    setPasswordChangeBusy(true);
    try {
      await unlockVault(currentMasterPassword);
      let nextServerSession = serverSession;
      if (serverSession) {
        const auth = await updateServerAccountPassword(
          serverSession,
          session.email,
          currentMasterPassword,
          nextMasterPassword,
        );
        nextServerSession = { baseUrl: serverSession.baseUrl, token: auth.token };
        setServerSession(nextServerSession);
        setServerStatus(text.status.connected);
      }

      const nextVault = await changeVaultPassword(
        session,
        items,
        currentMasterPassword,
        nextMasterPassword,
      );
      setSession(nextVault.session);
      if (nextServerSession) await pushVault(nextServerSession, nextVault.blob);
      await rememberUnlockedSession(nextVault.session, nextServerSession);
      setCurrentMasterPassword("");
      setNextMasterPassword("");
      setConfirmMasterPassword("");
      setPasswordChangeStatus(text.status.passwordChanged);
    } catch {
      setPasswordChangeStatus(text.status.passwordChangeFailed);
    } finally {
      setPasswordChangeBusy(false);
    }
  }

  async function connectServer() {
    if (!session || !serverPassword || serverConnectBusy) return;
    setServerConnectBusy(true);
    setServerStatus(text.status.connecting);
    try {
      const loginEmail = await resolveOwnerEmail(serverBaseUrl);
      let auth = await loginWithServer(serverBaseUrl, loginEmail, serverPassword).catch(async () => {
        return registerWithServer(serverBaseUrl, loginEmail, serverPassword);
      });
      const nextSession: ServerSession = { baseUrl: serverBaseUrl, token: auth.token };
      setServerSession(nextSession);
      setServerPassword("");
      setServerStatus(text.status.connected);
      const blob = await persistVault(session, items);
      const synced = await syncVaultWithServer(nextSession, { session, items, blob }, serverPassword);
      setSession(synced.session);
      setItems(synced.items);
      setSelectedId(synced.items[0]?.id ?? null);
      await rememberUnlockedSession(synced.session, nextSession);
      await loadTlsSettings(nextSession);
    } catch (error) {
      setServerStatus(error instanceof Error ? error.message : text.status.connectionFailed);
    } finally {
      setServerConnectBusy(false);
    }
  }

  async function loadTlsSettings(nextSession: ServerSession) {
    try {
      const settings = await getTlsSettings(nextSession);
      const current = settings.current;
      setTlsSite(current?.site ?? suggestedTlsSite(settings.defaultSite));
      setTlsCertificatePath(current?.certificatePath ?? "/app/data/certs/fullchain.pem");
      setTlsPrivateKeyPath(current?.privateKeyPath ?? "/app/data/certs/privkey.pem");
      setTlsTestId("");
      setTlsStatus(current ? text.status.saved : text.status.notTested);
    } catch (error) {
      setTlsStatus(error instanceof Error ? error.message : text.status.couldNotLoadTlsSettings);
    }
  }

  function currentTlsConfig(): TlsCertificateConfig {
    return {
      site: tlsSite,
      certificatePath: tlsCertificatePath,
      privateKeyPath: tlsPrivateKeyPath,
    };
  }

  function updateTlsForm(update: Partial<TlsCertificateConfig>) {
    if (update.site !== undefined) setTlsSite(update.site);
    if (update.certificatePath !== undefined) setTlsCertificatePath(update.certificatePath);
    if (update.privateKeyPath !== undefined) setTlsPrivateKeyPath(update.privateKeyPath);
    setTlsTestId("");
    setTlsStatus(text.status.notTested);
  }

  async function testTlsConfig() {
    if (!serverSession) {
      setTlsStatus(text.status.connectServerFirst);
      return;
    }
    setTlsBusy(true);
    setTlsStatus(text.status.testing);
    try {
      const result = await testTlsSettings(serverSession, currentTlsConfig());
      setTlsTestId(result.testId);
      setTlsStatus(result.ok ? text.status.testPassed : result.message);
    } catch (error) {
      setTlsTestId("");
      setTlsStatus(error instanceof Error ? error.message : text.status.testFailed);
    } finally {
      setTlsBusy(false);
    }
  }

  async function saveTlsConfig() {
    if (!serverSession) {
      setTlsStatus(text.status.connectServerFirst);
      return;
    }
    if (!tlsTestId) {
      setTlsStatus(text.status.runTestFirst);
      return;
    }
    setTlsBusy(true);
    setTlsStatus(text.status.saving);
    try {
      await saveTlsSettings(serverSession, { ...currentTlsConfig(), testId: tlsTestId });
      setTlsTestId("");
      setTlsStatus(text.status.savedAndReloaded);
    } catch (error) {
      setTlsStatus(error instanceof Error ? error.message : text.status.saveFailed);
    } finally {
      setTlsBusy(false);
    }
  }

  if (!resumeChecked) {
    return (
      <main className="auth-screen">
        <div className="ambient-layer" />
        <section className="auth-panel liquid-panel">
          <div className="brand-row">
            <div className="brand-mark">
              <ShieldCheck size={24} />
            </div>
            <div>
              <p className="eyebrow">NoPassword</p>
              <h1>{text.auth.privateVault}</h1>
            </div>
          </div>
          <div className="auth-resume-state" role="status">
            <RefreshCcw size={18} />
            <span>{text.auth.resuming}</span>
          </div>
        </section>
      </main>
    );
  }

  if (!session) {
    return (
      <main className="auth-screen">
        <div className="ambient-layer" />
        <section className="auth-panel liquid-panel">
          <div className="brand-row">
            <div className="brand-mark">
              <ShieldCheck size={24} />
            </div>
            <div>
              <p className="eyebrow">NoPassword</p>
              <h1>{text.auth.privateVault}</h1>
            </div>
          </div>

          <form onSubmit={handleAuth} className="auth-form">
            <div className="auth-password-label">
              <div className="auth-label-row">
                <label htmlFor="auth-password">{text.auth.loginPassword}</label>
              </div>
              <span className="password-field">
                <input
                  id="auth-password"
                  value={loginPassword}
                  onChange={(event) => setLoginPassword(event.target.value)}
                  type={showPassword ? "text" : "password"}
                  autoComplete={authPasswordAutocomplete}
                  minLength={8}
                  required
                />
                <button
                  type="button"
                  title={text.auth.togglePasswordVisibility}
                  aria-label={text.auth.togglePasswordVisibility}
                  onClick={() => setShowPassword((value) => !value)}
                >
                  {showPassword ? <EyeOff size={18} /> : <Eye size={18} />}
                </button>
              </span>
            </div>
            <p className="auth-note">{text.auth.loginPasswordHint}</p>
            <button
              className="primary-action"
              type="submit"
              aria-busy={authBusy}
              disabled={authBusy || !loginPassword.trim()}
            >
              <Lock size={18} />
              {authBusy ? text.status.connecting : authSubmitLabel}
            </button>
            <button
              type="button"
              className="auth-link-action"
              aria-haspopup="dialog"
              aria-expanded={resetPasswordModalOpen}
              onClick={() => setResetPasswordModalOpen(true)}
            >
              <Terminal size={16} />
              {text.auth.resetLoginPassword}
            </button>
            {authError && (
              <p className="form-error" role="alert">
                {authError}
              </p>
            )}
          </form>
        </section>

        {resetPasswordModalOpen && (
          <div
            className="modal-backdrop"
            onMouseDown={(event) => {
              if (event.target === event.currentTarget) setResetPasswordModalOpen(false);
            }}
          >
            <section
              className="reset-modal liquid-panel"
              role="dialog"
              aria-modal="true"
              aria-labelledby="reset-password-title"
              aria-describedby="reset-password-description"
            >
              <div className="modal-heading">
                <div className="modal-mark">
                  <Terminal size={20} />
                </div>
                <div>
                  <p className="eyebrow">{text.auth.resetModalEyebrow}</p>
                  <h2 id="reset-password-title">{text.auth.resetModalTitle}</h2>
                </div>
                <button
                  type="button"
                  className="modal-close"
                  title={text.actions.close}
                  aria-label={text.actions.close}
                  onClick={() => setResetPasswordModalOpen(false)}
                  autoFocus
                >
                  <X size={18} />
                </button>
              </div>

              <p id="reset-password-description" className="modal-lede">
                {text.auth.resetModalDescription}
              </p>

              <div className="command-card">
                <div className="command-card-heading">
                  <span>{text.auth.resetModalCommandLabel}</span>
                  <button
                    type="button"
                    onClick={() => copyValue(DOCKER_RESET_COMMAND, text.auth.resetCommandCopied)}
                  >
                    <Copy size={14} />
                    {text.auth.copyResetCommand}
                  </button>
                </div>
                <pre>
                  <code>{DOCKER_RESET_COMMAND}</code>
                </pre>
                {secureCopy === text.auth.resetCommandCopied && (
                  <span className="command-copy-state">
                    <Check size={14} />
                    {secureCopy}
                  </span>
                )}
              </div>

              <div className="modal-content-grid">
                <section className="modal-info-section">
                  <h3>{text.auth.resetModalStepsTitle}</h3>
                  <ol>
                    {text.auth.resetModalSteps.map((step) => (
                      <li key={step}>{step}</li>
                    ))}
                  </ol>
                </section>
                <section className="modal-info-section">
                  <h3>{text.auth.resetModalPreservesTitle}</h3>
                  <p>{text.auth.resetModalPreserves}</p>
                </section>
                <section className="modal-info-section warning">
                  <h3>{text.auth.resetModalWarningTitle}</h3>
                  <p>{text.auth.resetModalWarning}</p>
                </section>
              </div>
            </section>
          </div>
        )}
      </main>
    );
  }

  return (
    <main className="app-screen">
      <a className="skip-link" href="#main-content">
        {text.actions.skipToContent}
      </a>
      <div className="ambient-layer" />
      <aside className="sidebar liquid-panel">
        <div className="brand-row compact">
          <div className="brand-mark">
            <ShieldCheck size={22} />
          </div>
          <div>
            <p className="eyebrow">NoPassword</p>
            <strong>{text.nav.vault}</strong>
          </div>
        </div>

        <nav className="icon-nav" aria-label={text.nav.primary}>
          <button
            className={view === "vault" ? "active" : ""}
            onClick={() => setView("vault")}
            title={text.nav.vault}
            aria-current={view === "vault" ? "page" : undefined}
          >
            <KeyRound size={19} />
            <span>{text.nav.vault}</span>
          </button>
          <button
            className={view === "passkeys" ? "active" : ""}
            onClick={() => setView("passkeys")}
            title={text.nav.passkeys}
            aria-current={view === "passkeys" ? "page" : undefined}
          >
            <Fingerprint size={19} />
            <span>{text.nav.passkeys}</span>
          </button>
          <button
            className={view === "settings" ? "active" : ""}
            onClick={() => setView("settings")}
            title={text.nav.settings}
            aria-current={view === "settings" ? "page" : undefined}
          >
            <Settings size={19} />
            <span>{text.nav.settings}</span>
          </button>
        </nav>

        {view === "vault" && (
          <div className="sidebar-group">
            <p className="sidebar-label">{text.sections.browse}</p>
            <div className="category-list" role="tablist" aria-label={text.sections.vaultItems}>
              {categoryIds.map((id) => (
                <button
                  key={id}
                  className={category === id ? "active" : ""}
                  onClick={() => setCategory(id)}
                  aria-pressed={category === id}
                  aria-label={`${text.categories[id]} ${categoryCounts[id]}`}
                >
                  <span>{text.categories[id]}</span>
                  <small>{categoryCounts[id]}</small>
                </button>
              ))}
            </div>
          </div>
        )}

        <div className="sidebar-footer">
          <div className={`connection-chip ${connectionStatus.tone}`}>
            <ShieldCheck size={15} />
            <span>{connectionStatus.label}</span>
          </div>
          <button
            className="ghost-action"
            onClick={() => {
              forgetUnlockedSession();
              setAuthError("");
              setSession(null);
              setItems([]);
              setLoginPassword("");
              setServerSession(null);
              setServerStatus(text.status.notConnected);
            }}
          >
            <Lock size={17} />
            {text.actions.lock}
          </button>
        </div>
      </aside>

      {view === "vault" && (
        <section className="vault-shell" id="main-content" tabIndex={-1}>
          <header className="vault-overview liquid-strip" aria-label={text.sections.vaultOverview}>
            <div className="overview-identity">
              <p className="eyebrow">{text.sections.vaultOverview}</p>
              <h2>{session.email}</h2>
            </div>
            <div className="overview-metrics">
              <div className="overview-metric">
                <KeyRound size={18} />
                <span>{text.overview.items}</span>
                <strong>{items.length.toLocaleString()}</strong>
              </div>
              <div className="overview-metric">
                <Star size={18} />
                <span>{text.overview.starred}</span>
                <strong>{categoryCounts.favorites.toLocaleString()}</strong>
              </div>
              <div className="overview-metric">
                <RefreshCcw size={18} />
                <span>{text.overview.oneTimeCodes}</span>
                <strong>{otpItemCount.toLocaleString()}</strong>
              </div>
              <div className={`overview-metric ${connectionStatus.tone}`}>
                <ShieldCheck size={18} />
                <span>{text.overview.connection}</span>
                <strong>{connectionStatus.label}</strong>
              </div>
              <div className="overview-metric">
                <Database size={18} />
                <span>{text.overview.sync}</span>
                <strong>{serverSession ? serverStatus : text.status.notConnected}</strong>
              </div>
            </div>
          </header>

          <section className="list-pane liquid-panel">
            <header className="list-header">
              <div>
                <p className="eyebrow">{activeCategoryLabel}</p>
                <h2>{text.itemCount(filteredItems.length)}</h2>
              </div>
              <button
                className="icon-button"
                title={text.actions.addLogin}
                aria-label={text.actions.addLogin}
                onClick={() => addItem("login")}
              >
                <Plus size={18} />
              </button>
            </header>

            <div className="search-box">
              <Search size={17} />
              <input
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                placeholder={text.placeholders.searchVault}
                aria-label={text.placeholders.searchVault}
              />
            </div>

            <section className="item-list" aria-label={text.sections.vaultItems}>
              {filteredItems.map((item) => (
                <button
                  key={item.id}
                  className={`item-row ${selected?.id === item.id ? "active" : ""}`}
                  onClick={() => setSelectedId(item.id)}
                  aria-pressed={selected?.id === item.id}
                >
                  <span className="item-icon">
                    {item.kind === "secure-note" ? (
                      <Sparkles size={18} />
                    ) : item.kind === "card" ? (
                      <CreditCard size={18} />
                    ) : (
                      <Globe2 size={18} />
                    )}
                  </span>
                  <span className="item-copy">
                    <strong>{item.title}</strong>
                    <small>{item.username || item.url || text.itemKinds[item.kind]}</small>
                  </span>
                  <span className="item-kind">{text.itemKinds[item.kind]}</span>
                  {item.favorite && <Star size={16} fill="currentColor" />}
                </button>
              ))}
              {filteredItems.length === 0 && (
                <div className="empty-list">
                  <p>{text.empty.noItemsMatch}</p>
                  <button className="secondary-action" onClick={() => addItem("login")}>
                    <Plus size={17} />
                    {text.actions.addLogin}
                  </button>
                </div>
              )}
            </section>
          </section>

          <section className="detail-panel liquid-panel">
            {selected ? (
              <>
                <div className="detail-header">
                  <div className="detail-title-block">
                    <p className="eyebrow">{text.itemKinds[selected.kind]}</p>
                    <input
                      className="title-input"
                      aria-label={text.fields.title}
                      value={selected.title}
                      onChange={(event) => updateSelected({ title: event.target.value })}
                    />
                  </div>
                  <div className="detail-toolbar">
                    <button
                      title={text.actions.favorite}
                      aria-label={text.actions.favorite}
                      onClick={() => updateSelected({ favorite: !selected.favorite })}
                    >
                      <Star size={18} fill={selected.favorite ? "currentColor" : "none"} />
                    </button>
                    <button
                      title={text.actions.generatePassword}
                      aria-label={text.actions.generatePassword}
                      onClick={() => updateSelected({ password: generatePassword() })}
                    >
                      <Wand2 size={18} />
                    </button>
                    <button title={text.actions.addLogin} aria-label={text.actions.addLogin} onClick={() => addItem("login")}>
                      <Plus size={18} />
                    </button>
                  </div>
                </div>

                <div className="field-grid">
                  <label>
                    {text.fields.url}
                    <input
                      value={selected.url}
                      onChange={(event) => updateSelected({ url: event.target.value })}
                      type="url"
                      autoComplete="url"
                    />
                  </label>
                  <label>
                    {text.fields.username}
                    <div className="inline-field compact-field">
                      <input
                        value={selected.username}
                        onChange={(event) => updateSelected({ username: event.target.value })}
                        autoComplete="username"
                      />
                      <button
                        type="button"
                        title={text.actions.copyUsername}
                        aria-label={text.actions.copyUsername}
                        disabled={!selected.username}
                        onClick={() => copyValue(selected.username, text.actions.usernameCopied)}
                      >
                        <Copy size={16} />
                      </button>
                    </div>
                  </label>
                  <label>
                    {text.fields.password}
                    <div className="inline-field secret-field">
                      <input
                        value={selected.password}
                        onChange={(event) => updateSelected({ password: event.target.value })}
                        type={showPassword ? "text" : "password"}
                        autoComplete="off"
                      />
                      <button
                        type="button"
                        title={text.actions.copyPassword}
                        aria-label={text.actions.copyPassword}
                        disabled={!selected.password}
                        onClick={() => copyValue(selected.password, text.actions.passwordCopied)}
                      >
                        <Copy size={16} />
                      </button>
                      <button
                        type="button"
                        title={text.actions.generatePassword}
                        aria-label={text.actions.generatePassword}
                        onClick={() => updateSelected({ password: generatePassword() })}
                      >
                        <RefreshCcw size={16} />
                      </button>
                      <button
                        type="button"
                        title={showPassword ? text.actions.hidePassword : text.actions.revealPassword}
                        aria-label={showPassword ? text.actions.hidePassword : text.actions.revealPassword}
                        onClick={() => setShowPassword((value) => !value)}
                      >
                        {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                      </button>
                    </div>
                  </label>
                  <label>
                    {text.fields.otpSecret}
                    <input
                      value={selected.otpSecret ?? ""}
                      onChange={(event) => updateSelected({ otpSecret: event.target.value })}
                      placeholder={text.placeholders.otpSecret}
                      autoComplete="one-time-code"
                      spellCheck={false}
                    />
                  </label>
                  <div className="otp-card">
                    <div>
                      <p className="eyebrow">{text.sections.oneTimePassword}</p>
                      <strong>{otpCode?.code ?? text.sections.addSecret}</strong>
                    </div>
                    <div className="otp-actions">
                      <span>{otpCode ? `${otpCode.remaining}s` : "TOTP"}</span>
                      <button
                        type="button"
                        title={text.actions.copyOtp}
                        aria-label={text.actions.copyOtp}
                        disabled={!otpCode}
                        onClick={() => otpCode && copyValue(otpCode.code, text.actions.otpCopied)}
                      >
                        <Copy size={16} />
                      </button>
                    </div>
                  </div>
                  <label>
                    {text.fields.notes}
                    <textarea value={selected.notes} onChange={(event) => updateSelected({ notes: event.target.value })} />
                  </label>
                </div>

                <div className="detail-actions">
                  <button className="danger-action" onClick={deleteSelected}>
                    <Trash2 size={17} />
                    {text.actions.delete}
                  </button>
                  <span className={secureCopy ? "copy-state visible" : "copy-state"} aria-live="polite">
                    <Check size={16} />
                    {secureCopy}
                  </span>
                </div>
              </>
            ) : (
              <div className="empty-detail">
                <p className="eyebrow">{text.empty.noSelection}</p>
                <h2>{text.empty.addFirstItem}</h2>
                <button className="primary-action small" onClick={() => addItem("login")}>
                  <Plus size={18} />
                  {text.actions.addLogin}
                </button>
              </div>
            )}
          </section>
        </section>
      )}

      {view === "passkeys" && (
        <section className="secondary-view liquid-panel" id="main-content" tabIndex={-1}>
          <div className="section-heading">
            <div>
              <p className="eyebrow">{text.sections.passkeys}</p>
              <h2>{text.sections.trustedDevices}</h2>
            </div>
            <button className="primary-action small" onClick={addPasskey}>
              <Fingerprint size={18} />
              {text.actions.register}
            </button>
          </div>
          <div className="status-pill">
            <MonitorSmartphone size={17} />
            {passkeyStatus}
          </div>
          <div className="passkey-list">
            {passkeys.map((passkey) => (
              <div className="passkey-row" key={passkey.id}>
                <div>
                  <strong>{passkey.email}</strong>
                  <small>{passkey.rpId}</small>
                </div>
                <div>
                  <button
                    title={text.actions.verifyPasskey}
                    aria-label={text.actions.verifyPasskey}
                    onClick={() => testPasskey(passkey)}
                  >
                    <Check size={17} />
                  </button>
                  <button
                    title={text.actions.removePasskey}
                    aria-label={text.actions.removePasskey}
                    onClick={() => setPasskeys(removePasskey(passkey.id))}
                  >
                    <Trash2 size={17} />
                  </button>
                </div>
              </div>
            ))}
            {passkeys.length === 0 && <button className="empty-action" onClick={addPasskey}>{text.actions.register}</button>}
          </div>
        </section>
      )}

      {view === "settings" && (
        <section className="secondary-view liquid-panel" id="main-content" tabIndex={-1}>
          <div className="section-heading">
            <div>
              <p className="eyebrow">{text.sections.settings}</p>
              <h2>{text.sections.localVault}</h2>
            </div>
            <button className="danger-action" onClick={resetLocalVault}>
              <Trash2 size={17} />
              {text.actions.reset}
            </button>
          </div>
          <div className="settings-grid">
            <div className="setting-row">
              <span>{text.settings.vaultItems}</span>
              <strong>{items.length}</strong>
            </div>
          </div>
          <div className="admin-panel">
            <div className="section-heading compact-heading">
              <div>
                <p className="eyebrow">{text.sections.clients}</p>
                <h2>{text.sections.clientDownloads}</h2>
              </div>
            </div>
            <p className="panel-note">{text.sections.clientDownloadsDescription}</p>
            <div className="client-download-list">
              <div className="client-download-card">
                <span className="client-download-icon">
                  <Puzzle size={18} />
                </span>
                <span className="client-download-copy">
                  <strong>{text.settings.browserExtension}</strong>
                  <small>{text.settings.browserExtensionDescription}</small>
                </span>
                <a
                  className="secondary-action client-download-button"
                  href={BROWSER_EXTENSION_DOWNLOAD_URL}
                  download={BROWSER_EXTENSION_FILE_NAME}
                >
                  <Download size={17} />
                  {text.actions.download}
                </a>
              </div>
            </div>
          </div>
          <div className="admin-panel">
            <div className="section-heading compact-heading">
              <div>
                <p className="eyebrow">{text.sections.security}</p>
                <h2>{text.sections.accountName}</h2>
              </div>
              {accountEmailStatus && (
                <div className={accountEmailStatus === text.status.accountEmailChanged ? "status-pill compact passed" : "status-pill compact"}>
                  <AtSign size={17} />
                  {accountEmailStatus}
                </div>
              )}
            </div>
            <p className="panel-note">{text.sections.accountNameDescription}</p>
            <div className="admin-form">
              <label>
                {text.fields.accountEmail}
                <input
                  value={accountEmail}
                  onChange={(event) => setAccountEmail(event.target.value)}
                  type="email"
                  autoComplete="email"
                />
              </label>
              <button
                className="secondary-action"
                onClick={changeAccountEmail}
                aria-busy={accountEmailBusy}
                disabled={
                  accountEmailBusy ||
                  !accountEmail ||
                  accountEmail.trim().toLowerCase() === session.email.trim().toLowerCase()
                }
              >
                <AtSign size={17} />
                {accountEmailBusy ? text.status.saving : text.actions.changeAccountEmail}
              </button>
            </div>
          </div>
          <div className="admin-panel">
            <div className="section-heading compact-heading">
              <div>
                <p className="eyebrow">{text.sections.security}</p>
                <h2>{text.sections.password}</h2>
              </div>
              {passwordChangeStatus && (
                <div className={passwordChangeStatus === text.status.passwordChanged ? "status-pill compact passed" : "status-pill compact"}>
                  <ShieldCheck size={17} />
                  {passwordChangeStatus}
                </div>
              )}
            </div>
            <p className="panel-note">{text.sections.passwordDescription}</p>
            <div className="admin-form password-form">
              <label>
                {text.fields.currentPassword}
                <input
                  value={currentMasterPassword}
                  onChange={(event) => setCurrentMasterPassword(event.target.value)}
                  type="password"
                  autoComplete="current-password"
                />
              </label>
              <label>
                {text.fields.newPassword}
                <input
                  value={nextMasterPassword}
                  onChange={(event) => setNextMasterPassword(event.target.value)}
                  type="password"
                  autoComplete="new-password"
                  minLength={8}
                />
              </label>
              <label>
                {text.fields.confirmNewPassword}
                <input
                  value={confirmMasterPassword}
                  onChange={(event) => setConfirmMasterPassword(event.target.value)}
                  type="password"
                  autoComplete="new-password"
                  minLength={8}
                />
              </label>
              <button
                className="secondary-action"
                onClick={updateMasterPassword}
                aria-busy={passwordChangeBusy}
                disabled={
                  passwordChangeBusy ||
                  !currentMasterPassword ||
                  !nextMasterPassword ||
                  !confirmMasterPassword
                }
              >
                <Lock size={17} />
                {passwordChangeBusy ? text.status.saving : text.actions.changePassword}
              </button>
            </div>
          </div>
          <div className="admin-panel">
            <div className="section-heading compact-heading">
              <div>
                <p className="eyebrow">{text.sections.server}</p>
                <h2>{text.sections.tls}</h2>
              </div>
              <div className="status-pill compact">
                <Server size={17} />
                {serverStatus}
              </div>
            </div>
            <div className="admin-form">
              <label>
                {text.fields.serverUrl}
                <input
                  value={serverBaseUrl}
                  onChange={(event) => setServerBaseUrl(event.target.value)}
                  type="url"
                  autoComplete="url"
                />
              </label>
              <label>
                {text.auth.masterPassword}
                <input
                  value={serverPassword}
                  onChange={(event) => setServerPassword(event.target.value)}
                  type="password"
                  autoComplete="current-password"
                />
              </label>
              <button
                className="secondary-action"
                onClick={connectServer}
                aria-busy={serverConnectBusy}
                disabled={!serverPassword || serverConnectBusy}
              >
                <PlugZap size={17} />
                {serverConnectBusy ? text.status.connecting : text.actions.connect}
              </button>
            </div>

            <div className="admin-form tls-form">
              <label>
                {text.fields.siteUrl}
                <input
                  value={tlsSite}
                  onChange={(event) => updateTlsForm({ site: event.target.value })}
                  type="url"
                  autoComplete="url"
                />
              </label>
              <label>
                {text.fields.certificatePath}
                <input
                  value={tlsCertificatePath}
                  onChange={(event) => updateTlsForm({ certificatePath: event.target.value })}
                />
              </label>
              <label>
                {text.fields.privateKeyPath}
                <input
                  value={tlsPrivateKeyPath}
                  onChange={(event) => updateTlsForm({ privateKeyPath: event.target.value })}
                />
              </label>
              <div className="admin-actions">
                <button className="secondary-action" onClick={testTlsConfig} disabled={!serverSession || tlsBusy}>
                  <Check size={17} />
                  {text.actions.test}
                </button>
                <button className="primary-action small" onClick={saveTlsConfig} disabled={!serverSession || !tlsTestId || tlsBusy}>
                  <RefreshCcw size={17} />
                  {text.actions.saveAndReload}
                </button>
              </div>
              <div className={tlsTestId ? "status-pill compact passed" : "status-pill compact"}>
                <ShieldCheck size={17} />
                {tlsStatus}
              </div>
            </div>
          </div>
          <div className="admin-panel technical-panel">
            <div className="section-heading compact-heading">
              <div>
                <p className="eyebrow">{text.sections.advanced}</p>
                <h2>{text.sections.technicalInfo}</h2>
              </div>
            </div>
            <p className="panel-note">{text.sections.technicalInfoDescription}</p>
            <div className="settings-grid technical-grid">
              <div className="setting-row">
                <span>{text.settings.localVaultId}</span>
                <strong>{session.email}</strong>
              </div>
              <div className="setting-row">
                <span>{text.settings.kdf}</span>
                <strong>{session.kdf.name}</strong>
              </div>
              <div className="setting-row">
                <span>{text.settings.iterations}</span>
                <strong>{session.kdf.iterations.toLocaleString()}</strong>
              </div>
            </div>
          </div>
        </section>
      )}
    </main>
  );
}
