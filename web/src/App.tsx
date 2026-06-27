import { FormEvent, useEffect, useMemo, useState } from "react";
import {
  Check,
  Copy,
  Eye,
  EyeOff,
  Fingerprint,
  Globe2,
  KeyRound,
  Lock,
  MonitorSmartphone,
  PlugZap,
  Plus,
  RefreshCcw,
  Search,
  Server,
  Settings,
  ShieldCheck,
  Sparkles,
  Star,
  Trash2,
  Wand2,
} from "lucide-react";
import {
  getTlsSettings,
  loginWithServer,
  registerWithServer,
  saveTlsSettings,
  testTlsSettings,
  type ServerSession,
  type TlsCertificateConfig,
} from "./api";
import { generatePassword } from "./crypto";
import { getPasskeySupport, registerLocalPasskey, verifyLocalPasskey } from "./passkeys";
import {
  clearVault,
  createVault,
  hasVault,
  persistVault,
  readPasskeys,
  removePasskey,
  savePasskey,
  unlockVault,
} from "./store";
import { generateTotp } from "./totp";
import type { LocalPasskey, VaultItem, VaultItemKind, VaultSession } from "./types";

type AuthMode = "create" | "unlock";
type NavView = "vault" | "passkeys" | "settings";
type Category = "all" | VaultItemKind | "favorites" | "otp";

const categories: Array<{ id: Category; label: string }> = [
  { id: "all", label: "All" },
  { id: "favorites", label: "Starred" },
  { id: "login", label: "Logins" },
  { id: "otp", label: "OTP" },
  { id: "secure-note", label: "Notes" },
  { id: "passkey", label: "Passkeys" },
];

function suggestedTlsSite(defaultSite: string) {
  try {
    const url = new URL(defaultSite);
    if (url.hostname) {
      url.protocol = "https:";
      url.port = "";
      return url.toString().replace(/\/$/, "");
    }
  } catch {
    // Fall through to the current browser host.
  }
  return `https://${window.location.hostname || "localhost"}`;
}

export function App() {
  const [authMode, setAuthMode] = useState<AuthMode>(hasVault() ? "unlock" : "create");
  const [email, setEmail] = useState("alex@example.com");
  const [masterPassword, setMasterPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [authError, setAuthError] = useState("");
  const [session, setSession] = useState<VaultSession | null>(null);
  const [items, setItems] = useState<VaultItem[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [category, setCategory] = useState<Category>("all");
  const [view, setView] = useState<NavView>("vault");
  const [passkeys, setPasskeys] = useState<LocalPasskey[]>(readPasskeys());
  const [passkeyStatus, setPasskeyStatus] = useState("Checking");
  const [secureCopy, setSecureCopy] = useState("");
  const [otpCode, setOtpCode] = useState<{ code: string; remaining: number } | null>(null);
  const [serverBaseUrl, setServerBaseUrl] = useState(() => window.location.origin);
  const [serverPassword, setServerPassword] = useState("");
  const [serverSession, setServerSession] = useState<ServerSession | null>(null);
  const [serverStatus, setServerStatus] = useState("Not connected");
  const [tlsSite, setTlsSite] = useState("");
  const [tlsCertificatePath, setTlsCertificatePath] = useState("");
  const [tlsPrivateKeyPath, setTlsPrivateKeyPath] = useState("");
  const [tlsTestId, setTlsTestId] = useState("");
  const [tlsStatus, setTlsStatus] = useState("Not tested");
  const [tlsBusy, setTlsBusy] = useState(false);

  useEffect(() => {
    void getPasskeySupport().then((support) => {
      if (!support.supported) setPasskeyStatus("Unavailable");
      else if (!support.secureContext) setPasskeyStatus("Needs HTTPS");
      else if (!support.platformAuthenticator) setPasskeyStatus("External key ready");
      else setPasskeyStatus("Ready");
    });
  }, []);

  useEffect(() => {
    if (!session) return;
    const handle = window.setTimeout(() => {
      void persistVault(session, items);
    }, 200);
    return () => window.clearTimeout(handle);
  }, [items, session]);

  const selected = useMemo(
    () => items.find((item) => item.id === selectedId) ?? items[0] ?? null,
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

  async function handleAuth(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setAuthError("");
    try {
      const next =
        authMode === "create"
          ? await createVault(email, masterPassword)
          : await unlockVault(masterPassword);
      setSession(next.session);
      setItems(next.items);
      setSelectedId(next.items[0]?.id ?? null);
      setMasterPassword("");
    } catch {
      setAuthError("Unlock failed");
    }
  }

  function addItem(kind: VaultItemKind = "login") {
    const next: VaultItem = {
      id: crypto.randomUUID(),
      kind,
      title: kind === "secure-note" ? "Secure Note" : kind === "passkey" ? "New Passkey" : "New Login",
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
    const next = items.filter((item) => item.id !== selected.id);
    setItems(next);
    setSelectedId(next[0]?.id ?? null);
  }

  async function copyValue(value: string, label: string) {
    await navigator.clipboard.writeText(value);
    setSecureCopy(label);
    window.setTimeout(() => setSecureCopy(""), 1400);
  }

  async function addPasskey() {
    if (!session) return;
    try {
      const passkey = await registerLocalPasskey(session.email);
      setPasskeys(savePasskey(passkey));
      setPasskeyStatus("Linked");
    } catch {
      setPasskeyStatus("Cancelled");
    }
  }

  async function testPasskey(passkey: LocalPasskey) {
    try {
      const verified = await verifyLocalPasskey(passkey);
      setPasskeyStatus(verified ? "Verified" : "Not verified");
    } catch {
      setPasskeyStatus("Cancelled");
    }
  }

  async function connectServer() {
    if (!session || !serverPassword) return;
    setServerStatus("Connecting");
    try {
      let auth = await loginWithServer(serverBaseUrl, session.email, serverPassword).catch(async () => {
        return registerWithServer(serverBaseUrl, session.email, serverPassword);
      });
      const nextSession: ServerSession = { baseUrl: serverBaseUrl, token: auth.token };
      setServerSession(nextSession);
      setServerPassword("");
      setServerStatus("Connected");
      await loadTlsSettings(nextSession);
    } catch (error) {
      setServerStatus(error instanceof Error ? error.message : "Connection failed");
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
      setTlsStatus(current ? "Saved" : "Not tested");
    } catch (error) {
      setTlsStatus(error instanceof Error ? error.message : "Could not load TLS settings");
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
    setTlsStatus("Not tested");
  }

  async function testTlsConfig() {
    if (!serverSession) {
      setTlsStatus("Connect server first");
      return;
    }
    setTlsBusy(true);
    setTlsStatus("Testing");
    try {
      const result = await testTlsSettings(serverSession, currentTlsConfig());
      setTlsTestId(result.testId);
      setTlsStatus(result.ok ? "Test passed" : result.message);
    } catch (error) {
      setTlsTestId("");
      setTlsStatus(error instanceof Error ? error.message : "Test failed");
    } finally {
      setTlsBusy(false);
    }
  }

  async function saveTlsConfig() {
    if (!serverSession) {
      setTlsStatus("Connect server first");
      return;
    }
    if (!tlsTestId) {
      setTlsStatus("Run test first");
      return;
    }
    setTlsBusy(true);
    setTlsStatus("Saving");
    try {
      await saveTlsSettings(serverSession, { ...currentTlsConfig(), testId: tlsTestId });
      setTlsTestId("");
      setTlsStatus("Saved and reloaded");
    } catch (error) {
      setTlsStatus(error instanceof Error ? error.message : "Save failed");
    } finally {
      setTlsBusy(false);
    }
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
              <h1>Private vault</h1>
            </div>
          </div>

          <div className="mode-switch" aria-label="Authentication mode">
            <button className={authMode === "create" ? "active" : ""} onClick={() => setAuthMode("create")}>
              Create
            </button>
            <button className={authMode === "unlock" ? "active" : ""} onClick={() => setAuthMode("unlock")}>
              Unlock
            </button>
          </div>

          <form onSubmit={handleAuth} className="auth-form">
            {authMode === "create" && (
              <label>
                Email
                <input value={email} onChange={(event) => setEmail(event.target.value)} autoComplete="email" />
              </label>
            )}
            <label>
              Master password
              <span className="password-field">
                <input
                  value={masterPassword}
                  onChange={(event) => setMasterPassword(event.target.value)}
                  type={showPassword ? "text" : "password"}
                  autoComplete={authMode === "create" ? "new-password" : "current-password"}
                  minLength={8}
                  required
                />
                <button type="button" title="Toggle password visibility" onClick={() => setShowPassword((value) => !value)}>
                  {showPassword ? <EyeOff size={18} /> : <Eye size={18} />}
                </button>
              </span>
            </label>
            <button className="primary-action" type="submit">
              <Lock size={18} />
              {authMode === "create" ? "Create Vault" : "Unlock Vault"}
            </button>
            {authError && <p className="form-error">{authError}</p>}
          </form>
        </section>
      </main>
    );
  }

  return (
    <main className="app-screen">
      <div className="ambient-layer" />
      <aside className="sidebar liquid-panel">
        <div className="brand-row compact">
          <div className="brand-mark">
            <ShieldCheck size={22} />
          </div>
          <div>
            <p className="eyebrow">NoPassword</p>
            <strong>Vault</strong>
          </div>
        </div>

        <nav className="icon-nav" aria-label="Primary navigation">
          <button className={view === "vault" ? "active" : ""} onClick={() => setView("vault")} title="Vault">
            <KeyRound size={19} />
            <span>Vault</span>
          </button>
          <button className={view === "passkeys" ? "active" : ""} onClick={() => setView("passkeys")} title="Passkeys">
            <Fingerprint size={19} />
            <span>Passkeys</span>
          </button>
          <button className={view === "settings" ? "active" : ""} onClick={() => setView("settings")} title="Settings">
            <Settings size={19} />
            <span>Settings</span>
          </button>
        </nav>

        <div className="sidebar-footer">
          <button
            className="ghost-action"
            onClick={() => {
              setAuthMode("unlock");
              setAuthError("");
              setSession(null);
              setItems([]);
              setMasterPassword("");
            }}
          >
            <Lock size={17} />
            Lock
          </button>
        </div>
      </aside>

      {view === "vault" && (
        <section className="vault-shell">
          <header className="toolbar liquid-strip">
            <div className="search-box">
              <Search size={18} />
              <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search vault" />
            </div>
            <div className="toolbar-actions">
              <button title="Generate password" onClick={() => selected && updateSelected({ password: generatePassword() })}>
                <Wand2 size={18} />
              </button>
              <button title="Add login" onClick={() => addItem("login")}>
                <Plus size={18} />
              </button>
            </div>
          </header>

          <div className="category-row" role="tablist" aria-label="Vault categories">
            {categories.map((item) => (
              <button key={item.id} className={category === item.id ? "active" : ""} onClick={() => setCategory(item.id)}>
                {item.label}
              </button>
            ))}
          </div>

          <div className="vault-grid">
            <section className="item-list" aria-label="Vault items">
              {filteredItems.map((item) => (
                <button
                  key={item.id}
                  className={`item-row ${selected?.id === item.id ? "active" : ""}`}
                  onClick={() => setSelectedId(item.id)}
                >
                  <span className="item-icon">{item.kind === "secure-note" ? <Sparkles size={18} /> : <Globe2 size={18} />}</span>
                  <span>
                    <strong>{item.title}</strong>
                    <small>{item.username || item.url || item.kind}</small>
                  </span>
                  {item.favorite && <Star size={16} fill="currentColor" />}
                </button>
              ))}
            </section>

            <section className="detail-panel liquid-panel">
              {selected ? (
                <>
                  <div className="detail-header">
                    <div>
                      <p className="eyebrow">{selected.kind}</p>
                      <input
                        className="title-input"
                        value={selected.title}
                        onChange={(event) => updateSelected({ title: event.target.value })}
                      />
                    </div>
                    <button title="Favorite" onClick={() => updateSelected({ favorite: !selected.favorite })}>
                      <Star size={19} fill={selected.favorite ? "currentColor" : "none"} />
                    </button>
                  </div>

                  <div className="field-grid">
                    <label>
                      URL
                      <input value={selected.url} onChange={(event) => updateSelected({ url: event.target.value })} />
                    </label>
                    <label>
                      Username
                      <div className="inline-field">
                        <input value={selected.username} onChange={(event) => updateSelected({ username: event.target.value })} />
                        <button title="Copy username" onClick={() => copyValue(selected.username, "Username copied")}>
                          <Copy size={16} />
                        </button>
                      </div>
                    </label>
                    <label>
                      Password
                      <div className="inline-field">
                        <input
                          value={selected.password}
                          onChange={(event) => updateSelected({ password: event.target.value })}
                          type={showPassword ? "text" : "password"}
                        />
                        <button title="Copy password" onClick={() => copyValue(selected.password, "Password copied")}>
                          <Copy size={16} />
                        </button>
                        <button title="Generate password" onClick={() => updateSelected({ password: generatePassword() })}>
                          <RefreshCcw size={16} />
                        </button>
                      </div>
                    </label>
                    <label>
                      OTP Secret
                      <input
                        value={selected.otpSecret ?? ""}
                        onChange={(event) => updateSelected({ otpSecret: event.target.value })}
                        placeholder="Base32 secret or otpauth:// URI"
                        autoComplete="one-time-code"
                      />
                    </label>
                    <div className="otp-card">
                      <div>
                        <p className="eyebrow">One-time password</p>
                        <strong>{otpCode?.code ?? "Add secret"}</strong>
                      </div>
                      <div className="otp-actions">
                        <span>{otpCode ? `${otpCode.remaining}s` : "TOTP"}</span>
                        <button
                          title="Copy OTP"
                          disabled={!otpCode}
                          onClick={() => otpCode && copyValue(otpCode.code, "OTP copied")}
                        >
                          <Copy size={16} />
                        </button>
                      </div>
                    </div>
                    <label>
                      Notes
                      <textarea value={selected.notes} onChange={(event) => updateSelected({ notes: event.target.value })} />
                    </label>
                  </div>

                  <div className="detail-actions">
                    <button className="danger-action" onClick={deleteSelected}>
                      <Trash2 size={17} />
                      Delete
                    </button>
                    <span className={secureCopy ? "copy-state visible" : "copy-state"}>
                      <Check size={16} />
                      {secureCopy}
                    </span>
                  </div>
                </>
              ) : (
                <button className="empty-action" onClick={() => addItem("login")}>
                  <Plus size={18} />
                  Add Item
                </button>
              )}
            </section>
          </div>
        </section>
      )}

      {view === "passkeys" && (
        <section className="secondary-view liquid-panel">
          <div className="section-heading">
            <div>
              <p className="eyebrow">Passkeys</p>
              <h2>Trusted devices</h2>
            </div>
            <button className="primary-action small" onClick={addPasskey}>
              <Fingerprint size={18} />
              Register
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
                  <button title="Verify passkey" onClick={() => testPasskey(passkey)}>
                    <Check size={17} />
                  </button>
                  <button title="Remove passkey" onClick={() => setPasskeys(removePasskey(passkey.id))}>
                    <Trash2 size={17} />
                  </button>
                </div>
              </div>
            ))}
            {passkeys.length === 0 && <button className="empty-action" onClick={addPasskey}>Register Passkey</button>}
          </div>
        </section>
      )}

      {view === "settings" && (
        <section className="secondary-view liquid-panel">
          <div className="section-heading">
            <div>
              <p className="eyebrow">Settings</p>
              <h2>{session.email}</h2>
            </div>
            <button className="danger-action" onClick={() => { clearVault(); location.reload(); }}>
              <Trash2 size={17} />
              Reset
            </button>
          </div>
          <div className="settings-grid">
            <div className="setting-row">
              <span>KDF</span>
              <strong>{session.kdf.name}</strong>
            </div>
            <div className="setting-row">
              <span>Iterations</span>
              <strong>{session.kdf.iterations.toLocaleString()}</strong>
            </div>
            <div className="setting-row">
              <span>Vault Items</span>
              <strong>{items.length}</strong>
            </div>
            <div className="setting-row">
              <span>Install Mode</span>
              <strong>PWA Ready</strong>
            </div>
          </div>
          <div className="admin-panel">
            <div className="section-heading compact-heading">
              <div>
                <p className="eyebrow">Server</p>
                <h2>TLS</h2>
              </div>
              <div className="status-pill compact">
                <Server size={17} />
                {serverStatus}
              </div>
            </div>
            <div className="admin-form">
              <label>
                Server URL
                <input value={serverBaseUrl} onChange={(event) => setServerBaseUrl(event.target.value)} />
              </label>
              <label>
                Master password
                <input
                  value={serverPassword}
                  onChange={(event) => setServerPassword(event.target.value)}
                  type="password"
                  autoComplete="current-password"
                />
              </label>
              <button className="secondary-action" onClick={connectServer} disabled={!serverPassword}>
                <PlugZap size={17} />
                Connect
              </button>
            </div>

            <div className="admin-form tls-form">
              <label>
                Site URL
                <input value={tlsSite} onChange={(event) => updateTlsForm({ site: event.target.value })} />
              </label>
              <label>
                Certificate path
                <input
                  value={tlsCertificatePath}
                  onChange={(event) => updateTlsForm({ certificatePath: event.target.value })}
                />
              </label>
              <label>
                Private key path
                <input
                  value={tlsPrivateKeyPath}
                  onChange={(event) => updateTlsForm({ privateKeyPath: event.target.value })}
                />
              </label>
              <div className="admin-actions">
                <button className="secondary-action" onClick={testTlsConfig} disabled={!serverSession || tlsBusy}>
                  <Check size={17} />
                  Test
                </button>
                <button className="primary-action small" onClick={saveTlsConfig} disabled={!serverSession || !tlsTestId || tlsBusy}>
                  <RefreshCcw size={17} />
                  Save & Reload
                </button>
              </div>
              <div className={tlsTestId ? "status-pill compact passed" : "status-pill compact"}>
                <ShieldCheck size={17} />
                {tlsStatus}
              </div>
            </div>
          </div>
        </section>
      )}
    </main>
  );
}
