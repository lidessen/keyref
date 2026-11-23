import { createRuntime, keyed } from "meowjsx";
import { derived, mapSignal, signal } from "meowjsx/signal";
import { createWebRenderer } from "meowjsx/web";
import { Button, Input, Text, createMeowUI, meowUIComponents } from "meowtail";
import { standardTheme } from "meowtail/theme";
import { createMeowUITheme } from "meowtail/web";

interface Item {
  id: string;
  ref: string;
  masked: string;
  description?: string;
  allow_commands?: string[];
  size: number;
}
interface DeviceCode {
  user_code: string;
  verification_uri: string;
  expires_in: number;
  interval: number;
}

type Screen = "loading" | "signed-out" | "code" | "ready";
class APIError extends Error {
  constructor(readonly status: number, readonly code: string) { super(code); }
}
async function request<T>(path: string, method = "GET", body?: unknown): Promise<T> {
  const response = await fetch("/manage/api/" + path, {
    method,
    credentials: "same-origin",
    headers: method === "GET" ? {} : { "X-Keyref-Admin": "1", ...(body === undefined ? {} : { "Content-Type": "application/json" }) },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (!response.ok) {
    let code = "";
    try { code = (await response.json()).error ?? ""; } catch { /* Empty error response. */ }
    throw new APIError(response.status, code);
  }
  return response.status === 204 ? undefined as T : response.json() as Promise<T>;
}
function message(error: unknown): string {
  if (error instanceof APIError) {
    const descriptions: Record<string, string> = {
      forbidden: "This GitHub account does not have access to this vault.",
      access_denied: "GitHub authorization was declined.",
      expired_token: "The sign-in code expired. Start again to get a new one.",
      item_limit: "This vault is full. Delete an entry before adding another.",
      not_found: "This entry no longer exists. Refresh and try again.",
      conflict: "This reference already exists. Choose another reference.",
      invalid_request: "Check the reference, value, and allowed commands.",
    };
    return descriptions[error.code] ?? (error.status === 409 ? "This entry changed. Refresh and try again." : "The server could not complete the request. Try again.");
  }
  return "Could not reach the server. Check your connection and try again.";
}

function App() {
  const screen = signal<Screen>("loading");
  const items = signal<Item[]>([]);
  const query = signal("");
  const error = signal("");
  const notice = signal("");
  const busy = signal(false);
  const code = signal("");
  const editRef = signal("");
  const editID = signal("");
  const editing = signal(false);
  const confirmRef = signal("");
  const confirmID = signal("");
  let pollGeneration = 0;
  let opener: HTMLElement | null = null;
  const signedOut = derived(() => screen.value !== "signed-out");
  const signingIn = derived(() => screen.value !== "code");
  const loggedIn = derived(() => screen.value !== "ready");
  const loading = derived(() => screen.value !== "loading");
  const errorHidden = derived(() => error.value === "");
  const noticeHidden = derived(() => notice.value === "");
  const editorHidden = derived(() => !editing.value);
  const confirmHidden = derived(() => confirmRef.value === "");
  const editorTitle = derived(() => editRef.value ? "Edit credential" : "New credential");
  const secretHelp = derived(() => editRef.value ? "Leave blank to keep the current value." : "The value is encrypted before it is stored.");
  const refDisabled = derived(() => editRef.value !== "");
  const visibleItems = derived(() => {
    const search = query.value.trim().toLowerCase();
    return [...items.value].sort((a, b) => a.ref.localeCompare(b.ref)).filter((item) => !search || item.ref.toLowerCase().includes(search) || (item.description ?? "").toLowerCase().includes(search));
  });
  const empty = derived(() => visibleItems.value.length !== 0);
  const count = derived(() => `${visibleItems.value.length} ${visibleItems.value.length === 1 ? "credential" : "credentials"}`);
  const deleteMessage = derived(() => `Delete “${confirmRef.value}” from this vault? This cannot be undone.`);

  function clearMessages() { error.value = ""; notice.value = ""; }
  function fail(cause: unknown) {
    if (cause instanceof APIError && cause.status === 401) {
      pollGeneration++;
      items.value = [];
      editing.value = false;
      confirmRef.value = "";
      screen.value = "signed-out";
      error.value = "Your session has expired. Sign in again.";
    } else error.value = message(cause);
  }
  async function refresh() {
    try { items.value = await request<Item[]>("items"); screen.value = "ready"; }
    catch (cause) {
      if (cause instanceof APIError && cause.status === 401) { screen.value = "signed-out"; }
      else { screen.value = "signed-out"; error.value = message(cause); }
    }
  }
  async function login() {
    clearMessages();
    busy.value = true;
    try {
      const device = await request<DeviceCode>("login/device", "POST");
      const verification = new URL(device.verification_uri);
      if (verification.href !== "https://github.com/login/device") throw new Error("Invalid authorization URL");
      code.value = device.user_code;
      screen.value = "code";
      const generation = ++pollGeneration;
      const deadline = Date.now() + device.expires_in * 1000;
      let interval = Math.max(device.interval, 1) * 1000;
      while (generation === pollGeneration && Date.now() < deadline) {
        await new Promise((resolve) => setTimeout(resolve, interval));
        if (generation !== pollGeneration) return;
        try {
          await request<void>("login/poll", "POST");
          if (generation === pollGeneration) await refresh();
          return;
        } catch (cause) {
          if (cause instanceof APIError && cause.status === 409 && cause.code === "authorization_pending") continue;
          if (cause instanceof APIError && cause.status === 409 && cause.code === "slow_down") { interval += 5000; continue; }
          throw cause;
        }
      }
      if (generation === pollGeneration) { screen.value = "signed-out"; error.value = message(new APIError(409, "expired_token")); }
    } catch (cause) { screen.value = "signed-out"; error.value = message(cause); }
    finally { busy.value = false; }
  }
  async function logout() {
    clearMessages();
    try { await request("session", "DELETE"); }
    catch (cause) { if (!(cause instanceof APIError && cause.status === 401)) { fail(cause); return; } }
    pollGeneration++;
    items.value = [];
    query.value = "";
    editing.value = false;
    screen.value = "signed-out";
  }
  function openEditor(item?: Item) {
    clearMessages();
    opener = document.activeElement as HTMLElement | null;
    editRef.value = item?.ref ?? "";
    editID.value = item?.id ?? "";
    const form = document.querySelector<HTMLFormElement>("#credential-form")!;
    form.reset();
    (form.elements.namedItem("ref") as HTMLInputElement).value = item?.ref ?? "";
    (form.elements.namedItem("description") as HTMLInputElement).value = item?.description ?? "";
    (form.elements.namedItem("allow_commands") as HTMLInputElement).value = (item?.allow_commands ?? []).join(", ");
    editing.value = true;
    requestAnimationFrame(() => {
      if (!form.contains(document.activeElement)) (form.elements.namedItem(item ? "description" : "ref") as HTMLInputElement).focus();
    });
  }
  function closeEditor() {
    editing.value = false;
    document.querySelector<HTMLFormElement>("#credential-form")?.reset();
    opener?.focus();
  }
  function closeConfirmation() {
    confirmRef.value = "";
    opener?.focus();
  }
  document.addEventListener("keydown", (event) => {
    const modal = document.querySelector<HTMLElement>('.overlay:not([hidden]) .dialog');
    if (!modal) return;
    if (event.key === "Escape") {
      if (editing.value) closeEditor(); else closeConfirmation();
      return;
    }
    if (event.key !== "Tab") return;
    const controls = [...modal.querySelectorAll<HTMLElement>('button:not([disabled]), input:not([disabled]), a[href]')];
    if (controls.length === 0) return;
    if (event.shiftKey && document.activeElement === controls[0]) { event.preventDefault(); controls[controls.length - 1].focus(); }
    if (!event.shiftKey && document.activeElement === controls[controls.length - 1]) { event.preventDefault(); controls[0].focus(); }
  });
  async function save(event: Event) {
    event.preventDefault();
    if (busy.value) return;
    clearMessages();
    const form = event.currentTarget as HTMLFormElement;
    const fields = new FormData(form);
    const ref = editRef.value || String(fields.get("ref") ?? "").trim();
    const value = String(fields.get("value") ?? "");
    const allow_commands = String(fields.get("allow_commands") ?? "").split(",").map((command) => command.trim()).filter(Boolean);
    if (!/^(?:[a-z]|[a-z][a-z0-9-]{0,62}[a-z0-9])$/.test(ref)) { error.value = "Use 1–64 lowercase letters, numbers, or hyphens. Start with a letter and end with a letter or number."; return; }
    if (!editRef.value && !value) { error.value = "Enter a value for the new credential."; return; }
    busy.value = true;
    try {
      await request(editRef.value ? "items/" + encodeURIComponent(editID.value) : "items", editRef.value ? "PATCH" : "POST", {
        ref, description: String(fields.get("description") ?? ""), allow_commands, ...(value ? { value } : {}),
      });
      form.reset();
      closeEditor();
      await refresh();
      notice.value = editRef.value ? "Credential updated." : "Credential added.";
    } catch (cause) { fail(cause); }
    finally { busy.value = false; }
  }
  async function remove() {
    if (busy.value || !confirmRef.value) return;
    clearMessages();
    busy.value = true;
    try {
      await request("items/" + encodeURIComponent(confirmID.value), "DELETE");
      closeConfirmation();
      await refresh();
      notice.value = "Credential deleted.";
    } catch (cause) { fail(cause); }
    finally { busy.value = false; }
  }
  void refresh();

  return <div className="app">
    <header className="topbar">
      <div className="topbar-inner">
        <a href="/manage/" className="brand" aria-label="Keyref home"><img src="/manage/assets/logo.png" alt="" /><span>keyref</span></a>
        <div hidden={loggedIn}><Button variant="quiet" size="small" onClick={logout}>Sign out</Button></div>
      </div>
    </header>
    <main>
      <div className="alert error" role="alert" hidden={errorHidden}>{error}</div>
      <div className="alert notice" role="status" hidden={noticeHidden}>{notice}</div>
      <section className="loading" hidden={loading}><Text variant="secondary">Opening your vault…</Text></section>
      <section className="login-layout" hidden={signedOut}>
        <div className="login-copy">
          <p className="eyebrow">YOUR CREDENTIALS, KEPT CLOSE</p>
          <h1>Your credentials, in one place.</h1>
          <p className="lead">Sign in to manage the credentials your tools can use.</p>
          <Button variant="primary" disabled={busy} onClick={login}>Continue with GitHub <span aria-hidden="true">↗</span></Button>
          <p className="login-footnote">Sign in with your authorized GitHub account.</p>
        </div>
        <div className="mascot" aria-hidden="true"><img src="/manage/assets/logo.png" alt="" /></div>
      </section>
      <section className="code-panel" hidden={signingIn}>
        <p className="eyebrow">GITHUB SIGN IN</p>
        <h1>Connect your account</h1>
        <p className="lead">Enter this code on GitHub to open your vault.</p>
        <div className="device-code">{code}</div>
        <a className="github-link" href="https://github.com/login/device" target="_blank" rel="noopener noreferrer">Open GitHub <span aria-hidden="true">↗</span></a>
        <p className="waiting"><span className="pulse" />Waiting for authorization…</p>
        <Button variant="quiet" onClick={() => { pollGeneration++; busy.value = false; screen.value = "signed-out"; }}>Cancel</Button>
      </section>
      <section className="vault" hidden={loggedIn}>
        <div className="vault-heading">
          <div><p className="eyebrow">YOUR ACCOUNT VAULT</p><h1>Credentials</h1><p className="subheading">The keys your tools can use, all in one place.</p></div>
          <Button variant="primary" onClick={() => openEditor()}>＋ Add credential</Button>
        </div>
        <div className="toolbar">
          <div className="search"><label className="sr-only" htmlFor="search">Search credentials</label><span aria-hidden="true">⌕</span><Input id="search" type="search" placeholder="Search credentials" onInput={(event: Event) => { query.value = (event.target as HTMLInputElement).value; }} /></div>
          <Text variant="caption">{count}</Text>
        </div>
        <div className="empty" hidden={empty}><div className="empty-icon">✳</div><h2>No credentials found</h2><p>Add a credential or try a different search.</p><Button variant="outline" onClick={() => openEditor()}>Add credential</Button></div>
        <div className="credential-list">{keyed(visibleItems, (item) => item.ref, (item) => {
          const name = mapSignal(item, (value) => value.ref);
          const masked = mapSignal(item, (value) => value.masked);
          const description = mapSignal(item, (value) => value.description || "No description");
          const commands = mapSignal(item, (value) => value.allow_commands?.length ? value.allow_commands.join(", ") : "No commands allowed");
          return <article className="credential">
            <div className="entry-icon" aria-hidden="true">⌘</div>
            <div className="entry-main"><div className="entry-title"><strong>{name}</strong><code>{masked}</code></div><p>{description}</p><span className="entry-commands">Allowed: {commands}</span></div>
            <div className="entry-actions"><Button variant="outline" size="small" onClick={() => openEditor(item.value)}>Edit</Button><Button variant="quiet" size="small" onClick={() => { clearMessages(); opener = document.activeElement as HTMLElement | null; confirmRef.value = item.value.ref; confirmID.value = item.value.id; }}>Delete</Button></div>
          </article>;
        })}</div>
      </section>
      <div className="overlay" hidden={editorHidden}>
        <section className="dialog" role="dialog" aria-modal="true" aria-labelledby="editor-title">
          <div className="dialog-header"><div><p className="eyebrow">ACCOUNT VAULT</p><h2 id="editor-title">{editorTitle}</h2></div><button className="close" aria-label="Close" onClick={closeEditor}>×</button></div>
          <form id="credential-form" onSubmit={save}>
            <label htmlFor="ref">Reference</label><Input id="ref" name="ref" placeholder="e.g. openai-prod" disabled={refDisabled} autocomplete="off" /><small>Lowercase letters, numbers and hyphens.</small>
            <label htmlFor="value">Secret value</label><Input id="value" name="value" type="password" autocomplete="new-password" /><small>{secretHelp}</small>
            <label htmlFor="description">Description <span>optional</span></label><Input id="description" name="description" placeholder="What is this credential for?" />
            <label htmlFor="allow_commands">Allowed commands <span>optional</span></label><Input id="allow_commands" name="allow_commands" placeholder="curl, my-tool" /><small>Separate command names with commas.</small>
            <div className="dialog-actions"><Button type="button" variant="outline" onClick={closeEditor}>Cancel</Button><Button type="submit" variant="primary" disabled={busy}>Save credential</Button></div>
          </form>
        </section>
      </div>
      <div className="overlay" hidden={confirmHidden}>
        <section className="dialog confirm" role="dialog" aria-modal="true" aria-labelledby="confirm-title">
          <h2 id="confirm-title">Delete credential?</h2><p>{deleteMessage}</p>
          <div className="dialog-actions"><Button variant="outline" onClick={closeConfirmation}>Cancel</Button><Button variant="danger" disabled={busy} onClick={remove}>Delete credential</Button></div>
        </section>
      </div>
    </main>
  </div>;
}

const runtime = createRuntime({ plugins: [createMeowUI({ components: meowUIComponents }), createMeowUITheme({ theme: standardTheme })] });
createWebRenderer(runtime).render(<App />, document.querySelector<HTMLElement>("#app")!);
