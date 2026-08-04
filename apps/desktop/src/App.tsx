import { ChangeEvent, FormEvent, MouseEvent, useCallback, useEffect, useMemo, useState } from "react";
import TerminalPane from "./TerminalPane";
import type { AgentIdentity, CredentialSummary, Host, HostKeyProbe, SftpEntry } from "./api";
import {
  addHost,
  desktopAvailable,
  importAgentCredential,
  listAgentIdentities,
  listCredentials,
  listHosts,
  listSftpDirectory,
  probeHostKey,
  readSftpFile,
  trustHostKey,
  uploadSftpFile,
} from "./api";
import { credentialsForHost, formatTarget, hostInitial, remoteChild, remoteParent } from "./model";

const SFTP_PREVIEW_LIMIT = 1_048_576;
const SFTP_UPLOAD_LIMIT = 10 * 1024 * 1024;

type AppView = "home" | "session";
type SessionMode = "ssh" | "sftp";

export default function App() {
  const [hosts, setHosts] = useState<Host[]>([]);
  const [credentials, setCredentials] = useState<CredentialSummary[]>([]);
  const [selectedHostId, setSelectedHostId] = useState<string | null>(null);
  const [selectedCredentialId, setSelectedCredentialId] = useState<string | null>(null);
  const [view, setView] = useState<AppView>("home");
  const [sessionMode, setSessionMode] = useState<SessionMode>("ssh");
  const [search, setSearch] = useState("");
  const [status, setStatus] = useState("Loading local workspace…");
  const [connectSignal, setConnectSignal] = useState(0);
  const [pendingTrust, setPendingTrust] = useState<HostKeyProbe | null>(null);
  const [pendingMode, setPendingMode] = useState<SessionMode>("ssh");
  const [showAddHost, setShowAddHost] = useState(false);
  const [agentIdentities, setAgentIdentities] = useState<AgentIdentity[] | null>(null);
  const [sftpPath, setSftpPath] = useState("/");
  const [sftpEntries, setSftpEntries] = useState<SftpEntry[]>([]);
  const [sftpPreview, setSftpPreview] = useState<{ path: string; text: string } | null>(null);
  const [busy, setBusy] = useState(false);

  const selectedHost = hosts.find((host) => host.id === selectedHostId) ?? null;
  const availableCredentials = useMemo(
    () => credentialsForHost(credentials, selectedHostId),
    [credentials, selectedHostId],
  );
  const selectedCredential =
    availableCredentials.find((credential) => credential.id === selectedCredentialId) ??
    availableCredentials[0] ??
    null;
  const filteredHosts = useMemo(() => {
    const query = search.trim().toLocaleLowerCase();
    if (!query) return hosts;
    return hosts.filter((host) =>
      [host.label, host.target.host, host.target.username ?? "", host.environment ?? "", ...host.tags]
        .some((value) => value.toLocaleLowerCase().includes(query)),
    );
  }, [hosts, search]);
  const updateStatus = useCallback((value: string) => setStatus(value), []);

  const refresh = useCallback(async () => {
    const [nextHosts, nextCredentials] = await Promise.all([listHosts(), listCredentials()]);
    setHosts(nextHosts);
    setCredentials(nextCredentials);
    setSelectedHostId((current) => current ?? nextHosts[0]?.id ?? null);
    setStatus(
      desktopAvailable
        ? `${nextHosts.length} host${nextHosts.length === 1 ? "" : "s"} in local inventory`
        : "Browser preview — native actions are disabled",
    );
  }, []);

  useEffect(() => {
    void refresh().catch((error: unknown) => setStatus(String(error)));
  }, [refresh]);

  useEffect(() => {
    setPendingTrust(null);
    setSelectedCredentialId(availableCredentials[0]?.id ?? null);
  }, [selectedHostId, availableCredentials]);

  useEffect(() => {
    if (!showAddHost && agentIdentities === null) return;
    const dismissModal = (event: KeyboardEvent) => {
      if (event.key !== "Escape") return;
      setShowAddHost(false);
      setAgentIdentities(null);
    };
    window.addEventListener("keydown", dismissModal);
    return () => window.removeEventListener("keydown", dismissModal);
  }, [agentIdentities, showAddHost]);

  const loadSftpDirectory = async (path: string) => {
    if (!selectedHost || !selectedCredential) return;
    setBusy(true);
    setSftpPreview(null);
    try {
      const entries = await listSftpDirectory(selectedHost.id, selectedCredential.id, path);
      setSftpPath(path);
      setSftpEntries(entries);
      setStatus(`${entries.length} remote entr${entries.length === 1 ? "y" : "ies"} in ${path}`);
    } catch (error) {
      setStatus(`SFTP: ${String(error)}`);
    } finally {
      setBusy(false);
    }
  };

  const activateMode = async (mode: SessionMode) => {
    setView("session");
    setSessionMode(mode);
    if (mode === "ssh") {
      setConnectSignal((value) => value + 1);
    } else {
      await loadSftpDirectory("/");
    }
  };

  const openMode = async (mode: SessionMode) => {
    if (!selectedHost || !selectedCredential) {
      setStatus("Register an agent key for this host before connecting.");
      return;
    }
    setBusy(true);
    setPendingTrust(null);
    setPendingMode(mode);
    try {
      const probe = await probeHostKey(selectedHost.id);
      if (probe.accepted) {
        await activateMode(mode);
      } else if (probe.canTrustFirstUse) {
        setPendingTrust(probe);
        setView("session");
        setSessionMode(mode);
        setStatus("Review the first-use host fingerprint before continuing.");
      } else {
        setStatus(`Connection blocked by host-key policy: ${probe.decision}`);
      }
    } catch (error) {
      setStatus(String(error));
    } finally {
      setBusy(false);
    }
  };

  const trustAndContinue = async () => {
    if (!selectedHost) return;
    setBusy(true);
    try {
      await trustHostKey(selectedHost.id);
      setPendingTrust(null);
      await activateMode(pendingMode);
    } catch (error) {
      setStatus(String(error));
    } finally {
      setBusy(false);
    }
  };

  const registerAgentKey = async (identity: AgentIdentity) => {
    if (!selectedHost) return;
    setBusy(true);
    try {
      const label = identity.comment.trim() || `${selectedHost.label} agent key`;
      const credential = await importAgentCredential(label, identity.fingerprint, selectedHost.id);
      setCredentials((current) => [...current, credential]);
      setSelectedCredentialId(credential.id);
      setAgentIdentities(null);
      setStatus(`Registered ${identity.fingerprint}`);
    } catch (error) {
      setStatus(String(error));
    } finally {
      setBusy(false);
    }
  };

  const discoverAgentKeys = async () => {
    setBusy(true);
    try {
      setAgentIdentities(await listAgentIdentities());
    } catch (error) {
      setStatus(String(error));
    } finally {
      setBusy(false);
    }
  };

  const createHost = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    setBusy(true);
    try {
      const host = await addHost(
        String(form.get("label") ?? ""),
        String(form.get("target") ?? ""),
        String(form.get("environment") ?? "").trim() || null,
      );
      setHosts((current) => [...current, host].sort((a, b) => a.label.localeCompare(b.label)));
      setSelectedHostId(host.id);
      setShowAddHost(false);
      setStatus(`Added ${host.label}`);
    } catch (error) {
      setStatus(String(error));
    } finally {
      setBusy(false);
    }
  };

  const previewSftpFile = async (entry: SftpEntry) => {
    if (!selectedHost || !selectedCredential) return;
    setBusy(true);
    try {
      const contents = await readSftpFile(
        selectedHost.id,
        selectedCredential.id,
        entry.path,
        SFTP_PREVIEW_LIMIT,
      );
      let text: string;
      try {
        text = new TextDecoder("utf-8", { fatal: true }).decode(contents);
      } catch {
        text = `[Binary file · ${contents.byteLength} bytes · preview unavailable]`;
      }
      setSftpPreview({ path: entry.path, text });
      setStatus(`Previewed ${entry.path}`);
    } catch (error) {
      setStatus(`SFTP preview: ${String(error)}`);
    } finally {
      setBusy(false);
    }
  };

  const uploadSelectedFile = async (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    event.target.value = "";
    if (!file || !selectedHost || !selectedCredential) return;
    if (file.size > SFTP_UPLOAD_LIMIT) {
      setStatus(`SFTP upload is limited to ${SFTP_UPLOAD_LIMIT} bytes in the Desktop MVP.`);
      return;
    }
    setBusy(true);
    try {
      const remotePath = remoteChild(sftpPath, file.name);
      const result = await uploadSftpFile(
        selectedHost.id,
        selectedCredential.id,
        remotePath,
        new Uint8Array(await file.arrayBuffer()),
      );
      setStatus(`Uploaded ${result.bytesWritten} bytes to ${result.remotePath}`);
      setSftpEntries(await listSftpDirectory(selectedHost.id, selectedCredential.id, sftpPath));
    } catch (error) {
      setStatus(`SFTP upload: ${String(error)}`);
    } finally {
      setBusy(false);
    }
  };

  const selectHost = (host: Host) => {
    setSelectedHostId(host.id);
    setStatus(`${host.label} selected`);
  };

  const openHostMode = (event: MouseEvent, host: Host, mode: SessionMode) => {
    event.stopPropagation();
    setSelectedHostId(host.id);
    setView("session");
    setSessionMode(mode);
    setStatus(`${host.label} selected — choose or register a credential`);
  };

  return (
    <main className="app-shell">
      <header className="tab-bar" data-tauri-drag-region>
        <div className="window-drag-space" data-tauri-drag-region />
        <button className="brand-button" onClick={() => setView("home")} aria-label="YASC home">
          <span>›_</span>
        </button>
        <div className="top-tabs" data-tauri-drag-region>
          <button className={`top-tab ${view === "home" ? "active" : ""}`} onClick={() => setView("home")}>
            <span className="tab-icon">⌂</span> Home
          </button>
          {selectedHost && view === "session" && (
            <button className="top-tab active session-tab" onClick={() => setView("session")}>
              <span className={`host-avatar tiny ${selectedHost.environment ?? "default"}`}>{hostInitial(selectedHost)}</span>
              {selectedHost.label}
              <span className="tab-status" />
            </button>
          )}
          <button className="new-tab" onClick={() => setView("home")} aria-label="New tab">+</button>
        </div>
        <div className="global-status" title={status}>
          <span className="security-indicator" />
          <span>{status}</span>
        </div>
      </header>

      <aside className="app-nav">
        <nav>
          <button className="nav-item active"><span>▤</span> Hosts</button>
          <button className="nav-item" disabled><span>◇</span> Keychain <small>Soon</small></button>
          <button className="nav-item" disabled><span>⇄</span> Tunnels <small>Soon</small></button>
          <button className="nav-item" disabled><span>⌁</span> Snippets <small>Soon</small></button>
        </nav>
        <div className="nav-bottom">
          <button className="nav-item" disabled><span>⚙</span> Settings</button>
          <div className="local-profile">
            <span className="profile-avatar">Y</span>
            <span><strong>Local workspace</strong><small>Strict host keys</small></span>
          </div>
        </div>
      </aside>

      {view === "home" ? (
        <section className="home-workspace">
          <header className="home-toolbar">
            <label className="search-box">
              <span>⌕</span>
              <input
                value={search}
                onChange={(event) => setSearch(event.target.value)}
                placeholder="Search hosts, addresses, tags…"
                aria-label="Search hosts"
              />
              <kbd>⌘ K</kbd>
            </label>
            <div className="toolbar-actions">
              <button className="view-button active" aria-label="Grid view">⊞</button>
              <button className="view-button" aria-label="List view">☷</button>
              <button className="primary-button" onClick={() => setShowAddHost(true)}>+ New host</button>
            </div>
          </header>
          <div className="home-heading">
            <div>
              <span className="eyebrow">Workspace</span>
              <h1>All hosts</h1>
            </div>
            <p>{filteredHosts.length} connection{filteredHosts.length === 1 ? "" : "s"}</p>
          </div>
          <div className="host-grid">
            {filteredHosts.map((host) => (
              <article
                className={`host-card ${host.id === selectedHostId ? "selected" : ""}`}
                key={host.id}
                onClick={() => selectHost(host)}
              >
                <div className={`host-avatar ${host.environment ?? "default"}`}>{hostInitial(host)}</div>
                <div className="host-card-copy">
                  <strong>{host.label}</strong>
                  <span>SSH · {host.target.username ?? "user"}</span>
                  <small>{formatTarget(host)}</small>
                </div>
                <div className="host-card-actions">
                  <button onClick={(event) => openHostMode(event, host, "sftp")} title="Open files">▱</button>
                  <button onClick={(event) => openHostMode(event, host, "ssh")} title="Open SSH">›_</button>
                </div>
                {host.environment && <span className={`environment-tag ${host.environment}`}>{host.environment}</span>}
              </article>
            ))}
            <button className="add-host-card" onClick={() => setShowAddHost(true)}>
              <span>+</span>
              <strong>Add another host</strong>
              <small>SSH target and environment</small>
            </button>
            {filteredHosts.length === 0 && hosts.length > 0 && (
              <p className="empty-state">No hosts match “{search}”.</p>
            )}
          </div>
          {hosts.length === 0 && (
            <div className="welcome-empty">
              <span className="welcome-mark">›_</span>
              <h2>Your infrastructure, one workspace</h2>
              <p>Add an SSH host, keep its key in your agent, and use terminal and SFTP side by side.</p>
              <button className="primary-button" onClick={() => setShowAddHost(true)}>Add first host</button>
            </div>
          )}
        </section>
      ) : (
        <section className="session-workspace">
          <header className="session-toolbar">
            <div className="session-identity">
              <span className="connection-dot" />
              <div>
                <strong>{selectedHost?.label ?? "No host selected"}</strong>
                <small>{selectedHost ? formatTarget(selectedHost) : "Choose a host"}</small>
              </div>
            </div>
            <div className="mode-switch" aria-label="Session mode">
              <button className={sessionMode === "ssh" ? "active" : ""} onClick={() => setSessionMode("ssh")}>
                <span>▣</span> SSH
              </button>
              <button
                className={sessionMode === "sftp" ? "active" : ""}
                onClick={() => void openMode("sftp")}
                disabled={busy || !desktopAvailable}
              >
                <span>▱</span> SFTP
              </button>
              <button disabled><span>⇄</span> Tunnels</button>
            </div>
            <div className="session-actions">
              <label className="credential-select">
                <span>Credential</span>
                <select
                  value={selectedCredential?.id ?? ""}
                  onChange={(event) => setSelectedCredentialId(event.target.value)}
                  disabled={availableCredentials.length === 0}
                >
                  {availableCredentials.length === 0 && <option value="">No agent key</option>}
                  {availableCredentials.map((credential) => (
                    <option value={credential.id} key={credential.id}>{credential.label}</option>
                  ))}
                </select>
              </label>
              {availableCredentials.length === 0 && selectedHost && (
                <button className="secondary-button" onClick={discoverAgentKeys} disabled={busy || !desktopAvailable}>
                  Add key
                </button>
              )}
              <button
                className="connect-button"
                onClick={() => void openMode(sessionMode)}
                disabled={busy || !selectedHost || !desktopAvailable}
              >
                {busy ? "Working…" : sessionMode === "ssh" ? "Connect" : "Refresh"}
              </button>
            </div>
          </header>

          {pendingTrust && (
            <div className="trust-banner" role="alert">
              <div>
                <span className="eyebrow">First connection</span>
                <strong>Verify {pendingTrust.algorithm} fingerprint</strong>
                <code>{pendingTrust.fingerprint}</code>
              </div>
              <div className="trust-actions">
                <button className="ghost-button" onClick={() => setPendingTrust(null)}>Cancel</button>
                <button className="trust-button" onClick={trustAndContinue} disabled={busy}>Trust and continue</button>
              </div>
            </div>
          )}

          {sessionMode === "ssh" ? (
            <TerminalPane
              host={selectedHost}
              credential={selectedCredential}
              connectSignal={connectSignal}
              onStatus={updateStatus}
            />
          ) : (
            <div className="sftp-pane">
              <div className="sftp-toolbar">
                <div className="path-actions">
                  <button onClick={() => loadSftpDirectory(remoteParent(sftpPath))} disabled={busy || sftpPath === "/"}>‹</button>
                  <button onClick={() => loadSftpDirectory(sftpPath)} disabled={busy}>↻</button>
                </div>
                <code title={sftpPath}>{sftpPath}</code>
                <label className={`upload-button ${busy ? "disabled" : ""}`}>
                  Upload new
                  <input type="file" onChange={uploadSelectedFile} disabled={busy} aria-label="Upload a new remote file" />
                </label>
              </div>
              <div className="sftp-browser">
                <div className="sftp-list">
                  <div className="sftp-columns"><span>Name</span><span>Size</span><span>Permissions</span></div>
                  {sftpEntries.map((entry) => (
                    <button
                      key={entry.path}
                      className="sftp-row"
                      onClick={() => entry.kind === "directory" ? loadSftpDirectory(entry.path) : previewSftpFile(entry)}
                      disabled={busy || !["directory", "file"].includes(entry.kind)}
                    >
                      <span className="sftp-name"><i>{entry.kind === "directory" ? "▱" : "·"}</i>{entry.name}</span>
                      <span>{entry.kind === "directory" ? "—" : entry.size == null ? "—" : `${entry.size} B`}</span>
                      <code>{entry.permissions ?? "---------"}</code>
                    </button>
                  ))}
                  {sftpEntries.length === 0 && <p className="empty-state">Connect or refresh to browse this directory.</p>}
                </div>
                <div className="sftp-preview">
                  {sftpPreview ? (
                    <><strong>{sftpPreview.path}</strong><pre>{sftpPreview.text}</pre></>
                  ) : (
                    <div className="preview-empty"><span>▱</span><strong>File preview</strong><p>Select a file for a bounded 1 MiB UTF-8 preview.</p></div>
                  )}
                </div>
              </div>
            </div>
          )}
        </section>
      )}

      {showAddHost && (
        <div className="modal-backdrop" onMouseDown={() => setShowAddHost(false)}>
          <form className="modal-card" onSubmit={createHost} onMouseDown={(event) => event.stopPropagation()} role="dialog" aria-modal="true" aria-labelledby="add-host-title">
            <span className="eyebrow">Inventory</span>
            <h3 id="add-host-title">New SSH host</h3>
            <p className="modal-description">Add connection metadata now. Credentials stay separate and host-scoped.</p>
            <label>Label<input name="label" placeholder="Production API" required autoFocus /></label>
            <label>SSH target<input name="target" placeholder="deploy@example.com:22" required /></label>
            <label>Environment<input name="environment" placeholder="production" /></label>
            <div className="modal-actions">
              <button type="button" className="ghost-button" onClick={() => setShowAddHost(false)}>Cancel</button>
              <button className="primary-button" disabled={busy}>Add host</button>
            </div>
          </form>
        </div>
      )}

      {agentIdentities && (
        <div className="modal-backdrop" onMouseDown={() => setAgentIdentities(null)}>
          <div className="modal-card identity-card" onMouseDown={(event) => event.stopPropagation()} role="dialog" aria-modal="true" aria-labelledby="agent-identity-title">
            <span className="eyebrow">OpenSSH Agent</span>
            <h3 id="agent-identity-title">Select a public identity</h3>
            <p className="modal-description">The private key remains inside your agent.</p>
            <div className="identity-list">
              {agentIdentities.map((identity) => (
                <button key={identity.fingerprint} onClick={() => registerAgentKey(identity)} disabled={busy}>
                  <strong>{identity.comment || identity.algorithm}</strong>
                  <code>{identity.fingerprint}</code>
                </button>
              ))}
              {agentIdentities.length === 0 && <p className="empty-state">No identities are available.</p>}
            </div>
            <div className="modal-actions"><button className="ghost-button" onClick={() => setAgentIdentities(null)}>Close</button></div>
          </div>
        </div>
      )}
    </main>
  );
}
