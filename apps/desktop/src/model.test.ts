import { describe, expect, it } from "vitest";
import type { CredentialSummary, Host, LocalForward } from "./api";
import {
  credentialsForHost,
  formatBytes,
  formatTarget,
  hostInitial,
  localForwardsForHost,
  remoteChild,
  remoteParent,
  validTunnelPorts,
} from "./model";

const host: Host = {
  id: "host-1",
  label: "Production",
  target: { host: "example.com", port: 2200, username: "deploy" },
  tags: [],
  environment: "production",
};

describe("desktop view model", () => {
  it("formats an explicit SSH target without losing its port", () => {
    expect(formatTarget(host)).toBe("deploy@example.com:2200");
  });

  it("shows only native agent credentials granted to the selected host", () => {
    const credentials: CredentialSummary[] = [
      {
        id: "allowed",
        label: "Allowed agent",
        provider: "open_ssh_agent",
        hostIds: ["host-1"],
        externalKeyFingerprint: "SHA256:allowed",
        usableForNativeAgent: true,
      },
      {
        id: "wrong-host",
        label: "Wrong host",
        provider: "open_ssh_agent",
        hostIds: ["host-2"],
        externalKeyFingerprint: "SHA256:wrong",
        usableForNativeAgent: true,
      },
      {
        id: "vault",
        label: "Vault key",
        provider: "local_vault",
        hostIds: ["host-1"],
        externalKeyFingerprint: null,
        usableForNativeAgent: false,
      },
    ];

    expect(credentialsForHost(credentials, "host-1").map((item) => item.id)).toEqual(["allowed"]);
  });

  it("builds and traverses normalized remote paths", () => {
    expect(remoteChild("/", "var")).toBe("/var");
    expect(remoteChild("/var/", "log")).toBe("/var/log");
    expect(remoteParent("/var/log/")).toBe("/var");
    expect(remoteParent("/var")).toBe("/");
    expect(remoteParent("/")).toBe("/");
  });

  it("uses a stable host initial", () => {
    expect(hostInitial(host)).toBe("P");
    expect(hostInitial({ ...host, label: "  " })).toBe(">");
  });

  it("formats tunnel traffic at stable binary boundaries", () => {
    expect(formatBytes(1_023)).toBe("1023 B");
    expect(formatBytes(1_024)).toBe("1.0 KiB");
    expect(formatBytes(1_048_576)).toBe("1.0 MiB");
  });

  it("filters local forwards by their inventory host", () => {
    const base: LocalForward = {
      id: "forward-1",
      hostId: "host-1",
      credentialId: "credential-1",
      localAddress: "127.0.0.1:49152",
      remoteHost: "database.internal",
      remotePort: 5432,
      hostKeyStatus: "AcceptKnown",
      acceptedConnections: 1,
      activeConnections: 0,
      bytesFromLocal: 4,
      bytesToLocal: 4,
      failedConnections: 0,
      running: true,
    };
    expect(localForwardsForHost([base, { ...base, id: "forward-2", hostId: "host-2" }], "host-1"))
      .toEqual([base]);
    expect(localForwardsForHost([base], null)).toEqual([]);
  });

  it("accepts automatic local ports but rejects invalid destination ports", () => {
    expect(validTunnelPorts(0, 443)).toBe(true);
    expect(validTunnelPorts(65_535, 65_535)).toBe(true);
    expect(validTunnelPorts(-1, 443)).toBe(false);
    expect(validTunnelPorts(8080, 0)).toBe(false);
    expect(validTunnelPorts(8080.5, 443)).toBe(false);
  });
});
