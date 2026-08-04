import { FormEvent, useCallback, useEffect, useMemo, useState } from "react";
import TerminalPane from "./TerminalPane";
import type { AgentIdentity, CredentialSummary, Host, HostKeyProbe } from "./api";
import {
  addHost,
  desktopAvailable,
  importAgentCredential,
  listAgentIdentities,
  listCredentials,
  listHosts,
  probeHostKey,
  trustHostKey,
} from "./api";
import { credentialsForHost, formatTarget } from "./model";

export default function App() {
  const [hosts, setHosts] = useState<Host[]>([]);
  const [credentials, setCredentials] = useState<CredentialSummary[]>([]);
  const [selectedHostId, setSelectedHostId] = useState<string | null>(null);
  const [selectedCredentialId, setSelectedCredentialId] = useState<string | null>(null);
  const [status, setStatus] = useState("Loading local workspace…");
  const [connectSignal, setConnectSignal] = useState(0);
  const [pendingTrust, setPendingTrust] = useState<HostKeyProbe | null>(null);
  const [showAddHost, setShowAddHost] = useState(false);
  const [agentIdentities, setAgentIdentities] = useState<AgentIdentity[] | null>(null);
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

  const connect = async () => {
    if (!selectedHost || !selectedCredential) {
      setStatus("Register an agent key for this host before connecting.");
      return;
    }
    setBusy(true);
    setPendingTrust(null);
    try {
      const probe = await probeHostKey(selectedHost.id);
      if (probe.accepted) {
        setConnectSignal((value) => value + 1);
      } else if (probe.canTrustFirstUse) {
        setPendingTrust(probe);
        setStatus("Review the first-use host fingerprint before trusting it.");
      } else {
        setStatus(`Connection blocked by host-key policy: ${probe.decision}`);
      }
    } catch (error) {
      setStatus(String(error));
    } finally {
      setBusy(false);
    }
  };

  const trustAndConnect = async () => {
    if (!selectedHost) return;
    setBusy(true);
    try {
      await trustHostKey(selectedHost.id);
      setPendingTrust(null);
      setConnectSignal((value) => value + 1);
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
      const credential = await importAgentCredential(
        label,
        identity.fingerprint,
        selectedHost.id,
      );
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

  return (
    <main className="app-shell">
      <header className="titlebar" data-tauri-drag-region>
        <div className="brand" data-tauri-drag-region>
          <span className="brand-mark" aria-hidden="true">›_</span>
          <span>YASC</span>
          <span className="mvp-label">macOS MVP</span>
        </div>
        <div className="status-pill" title={status}>{status}</div>
      </header>

      <aside className="sidebar">
        <div className="sidebar-heading">
          <div>
            <span className="eyebrow">Workspace</span>
            <h1>Hosts</h1>
          </div>
          <button className="icon-button" onClick={() => setShowAddHost(true)} aria-label="Add host">+</button>
        </div>
        <div className="host-list">
          {hosts.map((host) => (
            <button
              className={`host-row ${host.id === selectedHostId ? "selected" : ""}`}
              key={host.id}
              onClick={() => setSelectedHostId(host.id)}
            >
              <span className={`environment-dot ${host.environment ?? "default"}`} />
              <span className="host-copy">
                <strong>{host.label}</strong>
                <small>{formatTarget(host)}</small>
              </span>
              <span className="chevron">›</span>
            </button>
          ))}
          {hosts.length === 0 && <p className="empty-state">Add a host to begin.</p>}
        </div>
        <div className="sidebar-footer">
          <span className="security-indicator" />
          Local workspace · strict host keys
        </div>
      </aside>

      <section className="workspace">
        <div className="connection-bar">
          <div className="connection-identity">
            <span className="eyebrow">Direct SSH</span>
            <h2>{selectedHost?.label ?? "No host selected"}</h2>
            <p>{selectedHost ? formatTarget(selectedHost) : "Choose a host from the sidebar"}</p>
          </div>
          <div className="connection-actions">
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
                Add agent key
              </button>
            )}
            <button className="connect-button" onClick={connect} disabled={busy || !selectedHost || !desktopAvailable}>
              <span className="play-icon">▶</span>
              Connect
            </button>
          </div>
        </div>

        {pendingTrust && (
          <div className="trust-banner" role="alert">
            <div>
              <span className="eyebrow">First connection</span>
              <strong>Verify {pendingTrust.algorithm} fingerprint</strong>
              <code>{pendingTrust.fingerprint}</code>
            </div>
            <div className="trust-actions">
              <button className="ghost-button" onClick={() => setPendingTrust(null)}>Cancel</button>
              <button className="trust-button" onClick={trustAndConnect} disabled={busy}>Trust and connect</button>
            </div>
          </div>
        )}

        <TerminalPane
          host={selectedHost}
          credential={selectedCredential}
          connectSignal={connectSignal}
          onStatus={updateStatus}
        />
      </section>

      {showAddHost && (
        <div className="modal-backdrop" onMouseDown={() => setShowAddHost(false)}>
          <form
            className="modal-card"
            onSubmit={createHost}
            onMouseDown={(event) => event.stopPropagation()}
            role="dialog"
            aria-modal="true"
            aria-labelledby="add-host-title"
          >
            <span className="eyebrow">Inventory</span>
            <h3 id="add-host-title">Add a host</h3>
            <label>Label<input name="label" placeholder="Production API" required autoFocus /></label>
            <label>SSH target<input name="target" placeholder="deploy@example.com:22" required /></label>
            <label>Environment<input name="environment" placeholder="production" /></label>
            <div className="modal-actions">
              <button type="button" className="ghost-button" onClick={() => setShowAddHost(false)}>Cancel</button>
              <button className="connect-button" disabled={busy}>Add host</button>
            </div>
          </form>
        </div>
      )}

      {agentIdentities && (
        <div className="modal-backdrop" onMouseDown={() => setAgentIdentities(null)}>
          <div
            className="modal-card identity-card"
            onMouseDown={(event) => event.stopPropagation()}
            role="dialog"
            aria-modal="true"
            aria-labelledby="agent-identity-title"
          >
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
            <div className="modal-actions">
              <button className="ghost-button" onClick={() => setAgentIdentities(null)}>Close</button>
            </div>
          </div>
        </div>
      )}
    </main>
  );
}
