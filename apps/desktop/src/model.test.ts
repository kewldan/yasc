import { describe, expect, it } from "vitest";
import type { CredentialSummary, Host } from "./api";
import {
  credentialsForHost,
  formatTarget,
  hostInitial,
  remoteChild,
  remoteParent,
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
});
