import { Channel, invoke } from "@tauri-apps/api/core";

export type SshTarget = {
  host: string;
  port: number;
  username: string | null;
};

export type Host = {
  id: string;
  label: string;
  target: SshTarget;
  tags: string[];
  environment: string | null;
};

export type CredentialSummary = {
  id: string;
  label: string;
  provider: string;
  hostIds: string[];
  externalKeyFingerprint: string | null;
  usableForNativeAgent: boolean;
};

export type AgentIdentity = {
  algorithm: string;
  comment: string;
  fingerprint: string;
};

export type HostKeyProbe = {
  fingerprint: string;
  algorithm: string;
  decision: string;
  accepted: boolean;
  canTrustFirstUse: boolean;
};

export type TerminalEvent =
  | { type: "data"; stream: "stdout" | "stderr"; data: number[] }
  | { type: "exit"; status: number }
  | { type: "error"; message: string };

const isDesktop = "__TAURI_INTERNALS__" in window;

const previewHosts: Host[] = [
  {
    id: "preview-production",
    label: "Production edge",
    target: { host: "203.0.113.24", port: 22, username: "deploy" },
    tags: ["production", "linux"],
    environment: "production",
  },
  {
    id: "preview-staging",
    label: "Staging API",
    target: { host: "192.0.2.18", port: 2202, username: "ops" },
    tags: ["staging"],
    environment: "staging",
  },
];

export const desktopAvailable = isDesktop;

export async function listHosts(): Promise<Host[]> {
  return isDesktop ? invoke<Host[]>("list_hosts") : previewHosts;
}

export async function addHost(
  label: string,
  target: string,
  environment: string | null,
): Promise<Host> {
  if (!isDesktop) {
    throw new Error("Host creation is available in the desktop build.");
  }
  return invoke<Host>("add_host", { label, target, environment });
}

export async function listCredentials(): Promise<CredentialSummary[]> {
  return isDesktop ? invoke<CredentialSummary[]>("list_credentials") : [];
}

export async function listAgentIdentities(): Promise<AgentIdentity[]> {
  if (!isDesktop) return [];
  return invoke<AgentIdentity[]>("list_agent_identities", { provider: "openssh" });
}

export async function importAgentCredential(
  label: string,
  fingerprint: string,
  hostId: string,
): Promise<CredentialSummary> {
  return invoke<CredentialSummary>("import_agent_credential", {
    label,
    fingerprint,
    hostId,
    provider: "openssh",
  });
}

export async function probeHostKey(hostId: string): Promise<HostKeyProbe> {
  return invoke<HostKeyProbe>("probe_host_key", { hostId });
}

export async function trustHostKey(hostId: string): Promise<HostKeyProbe> {
  return invoke<HostKeyProbe>("trust_host_key", { hostId });
}

export async function startAgentSession(
  hostId: string,
  credentialId: string,
  columns: number,
  rows: number,
  terminalType: string,
  onEvent: (event: TerminalEvent) => void,
): Promise<string> {
  const channel = new Channel<TerminalEvent>();
  channel.onmessage = onEvent;
  return invoke<string>("start_agent_session", {
    hostId,
    credentialId,
    columns,
    rows,
    terminalType,
    onEvent: channel,
  });
}

export async function writeSession(sessionId: string, data: Uint8Array): Promise<void> {
  await invoke("write_session", { sessionId, data: Array.from(data) });
}

export async function resizeSession(
  sessionId: string,
  columns: number,
  rows: number,
): Promise<void> {
  await invoke("resize_session", { sessionId, columns, rows });
}

export async function closeSession(sessionId: string): Promise<void> {
  await invoke("close_session", { sessionId });
}
