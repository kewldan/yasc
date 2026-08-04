import type { CredentialSummary, Host } from "./api";

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
