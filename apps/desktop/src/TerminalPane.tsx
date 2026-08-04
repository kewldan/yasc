import { useEffect, useRef } from "react";
import { FitAddon } from "@xterm/addon-fit";
import { Terminal } from "@xterm/xterm";
import type { CredentialSummary, Host, TerminalEvent } from "./api";
import {
  closeSession,
  resizeSession,
  startAgentSession,
  writeSession,
} from "./api";

type Props = {
  host: Host | null;
  credential: CredentialSummary | null;
  connectSignal: number;
  onStatus: (status: string) => void;
};

export default function TerminalPane({ host, credential, connectSignal, onStatus }: Props) {
  const container = useRef<HTMLDivElement>(null);
  const terminal = useRef<Terminal | null>(null);
  const fit = useRef<FitAddon | null>(null);
  const sessionId = useRef<string | null>(null);
  const writeQueue = useRef(Promise.resolve());
  const connectionAttempt = useRef(0);

  useEffect(() => {
    if (!container.current) return;
    const instance = new Terminal({
      allowProposedApi: false,
      convertEol: false,
      cursorBlink: true,
      cursorStyle: "bar",
      fontFamily: '"SFMono-Regular", "SF Mono", Menlo, monospace',
      fontSize: 13,
      lineHeight: 1.25,
      scrollback: 5000,
      theme: {
        background: "#080b10",
        foreground: "#dce7e6",
        cursor: "#45e0cd",
        cursorAccent: "#080b10",
        selectionBackground: "#1f6f6888",
        black: "#111720",
        red: "#ff6b7a",
        green: "#59d499",
        yellow: "#e7c96a",
        blue: "#6ca8ff",
        magenta: "#bf8cff",
        cyan: "#45e0cd",
        white: "#dce7e6",
      },
    });
    const fitAddon = new FitAddon();
    instance.loadAddon(fitAddon);
    instance.open(container.current);
    instance.writeln("\x1b[38;2;69;224;205mYASC\x1b[0m desktop terminal ready.");
    instance.writeln("Select a host and an external-agent credential to connect.\r\n");
    terminal.current = instance;
    fit.current = fitAddon;
    requestAnimationFrame(() => fitAddon.fit());

    const inputSubscription = instance.onData((value) => {
      const activeSession = sessionId.current;
      if (!activeSession) return;
      const bytes = new TextEncoder().encode(value);
      writeQueue.current = writeQueue.current
        .then(() => writeSession(activeSession, bytes))
        .catch((error: unknown) => {
          onStatus(String(error));
        });
    });
    const resizeObserver = new ResizeObserver(() => {
      fitAddon.fit();
      const activeSession = sessionId.current;
      if (activeSession) {
        void resizeSession(activeSession, instance.cols, instance.rows).catch((error: unknown) =>
          onStatus(String(error)),
        );
      }
    });
    resizeObserver.observe(container.current);

    return () => {
      connectionAttempt.current += 1;
      resizeObserver.disconnect();
      inputSubscription.dispose();
      const activeSession = sessionId.current;
      if (activeSession) void closeSession(activeSession);
      instance.dispose();
      terminal.current = null;
      fit.current = null;
    };
  }, [onStatus]);

  useEffect(() => {
    if (connectSignal === 0 || !host || !credential || !terminal.current) return;
    const instance = terminal.current;
    const attempt = connectionAttempt.current + 1;
    connectionAttempt.current = attempt;
    const previousSession = sessionId.current;
    sessionId.current = null;
    let finishedBeforeReady = false;
    fit.current?.fit();
    instance.reset();
    instance.writeln(`\x1b[38;2;69;224;205mConnecting to ${host.label}…\x1b[0m`);
    onStatus("Starting native SSH session…");
    const handleEvent = (event: TerminalEvent) => {
      if (connectionAttempt.current !== attempt) return;
      if (event.type === "data") {
        instance.write(Uint8Array.from(event.data));
      } else if (event.type === "exit") {
        finishedBeforeReady = true;
        instance.writeln(`\r\n\x1b[2mSession exited with status ${event.status}.\x1b[0m`);
        sessionId.current = null;
        onStatus(`Session exited with status ${event.status}`);
      } else {
        finishedBeforeReady = true;
        instance.writeln(`\r\n\x1b[31m${event.message}\x1b[0m`);
        sessionId.current = null;
        onStatus(event.message);
      }
    };
    void (async () => {
      if (previousSession) {
        await closeSession(previousSession).catch(() => undefined);
      }
      if (connectionAttempt.current !== attempt) return null;
      return startAgentSession(
        host.id,
        credential.id,
        instance.cols,
        instance.rows,
        "xterm-256color",
        handleEvent,
      );
    })()
      .then((id) => {
        if (id === null) return;
        if (connectionAttempt.current !== attempt) {
          void closeSession(id).catch(() => undefined);
          return;
        }
        if (finishedBeforeReady) return;
        sessionId.current = id;
        onStatus(`Connected to ${host.label}`);
        instance.focus();
      })
      .catch((error: unknown) => {
        if (connectionAttempt.current !== attempt) return;
        instance.writeln(`\r\n\x1b[31m${String(error)}\x1b[0m`);
        onStatus(String(error));
      });
  }, [connectSignal, credential, host, onStatus]);

  return <div className="terminal-surface" ref={container} aria-label="SSH terminal" />;
}
