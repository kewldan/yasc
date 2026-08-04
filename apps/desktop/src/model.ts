import type { CredentialSummary, Host, LocalForward } from "./api";

export function formatTarget(host: Host): string {
  const user = host.target.username ? `${host.target.username}@` : "";
  const port = host.target.port === 22 ? "" : `:${host.target.port}`;
  return `${user}${host.target.host}${port}`;
}

export function credentialsForHost(
  credentials: CredentialSummary[],
  hostId: string | null,
): CredentialSummary[] {
  if (hostId === null) return [];
  return credentials.filter(
    (credential) => credential.usableForNativeAgent && credential.hostIds.includes(hostId),
  );
}

export function remoteParent(path: string): string {
  if (path === "/" || path === ".") return "/";
  const normalized = path.replace(/\/+$/, "");
  const split = normalized.lastIndexOf("/");
  return split <= 0 ? "/" : normalized.slice(0, split);
}

export function remoteChild(parent: string, name: string): string {
  return parent === "/" ? `/${name}` : `${parent.replace(/\/+$/, "")}/${name}`;
}

export function hostInitial(host: Host): string {
  return host.label.trim().slice(0, 1).toUpperCase() || ">";
}

export function formatBytes(value: number): string {
  if (value < 1_024) return `${value} B`;
  if (value < 1_048_576) return `${(value / 1_024).toFixed(1)} KiB`;
  return `${(value / 1_048_576).toFixed(1)} MiB`;
}

export function localForwardsForHost(
  forwards: LocalForward[],
  hostId: string | null,
): LocalForward[] {
  if (hostId === null) return [];
  return forwards.filter((forward) => forward.hostId === hostId);
}

export function validTunnelPorts(localPort: number, remotePort: number): boolean {
  return (
    Number.isInteger(localPort) &&
    localPort >= 0 &&
    localPort <= 65_535 &&
    Number.isInteger(remotePort) &&
    remotePort >= 1 &&
    remotePort <= 65_535
  );
}
