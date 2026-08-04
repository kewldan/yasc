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
