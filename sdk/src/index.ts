/**
 * LatticeAGI Watch SDK — thin client over the control socket (§3.1).
 *
 * Transport: AF_UNIX SOCK_STREAM, 4-byte big-endian length prefix followed
 * by canonical JSON (watch/1). One in-flight request per connection.
 *
 * The SDK never fabricates results: every call is a real RPC to watchd.
 * The offline `verify` proof pipeline is exposed via `watchctl verify`
 * (Rust core); this package deliberately does not reimplement it.
 */

import { createConnection, Socket } from "node:net";
import { randomUUID } from "node:crypto";

export const PROTOCOL = "watch/1" as const;
export const REQUEST_MAX = 1_048_576;
export const REPLY_MAX = 8_388_608;

export type Role = "operator" | "runtime" | "reviewer" | "auditor";

export interface Reply<T = unknown> {
  v: 1;
  id: string;
  ok: boolean;
  result?: T;
  error?: {
    code: string;
    message: string;
    retryable: boolean;
    retry_after_ms: number | null;
  };
}

export class WatchError extends Error {
  constructor(
    public code: string,
    message: string,
    public retryable = false,
    public retryAfterMs: number | null = null,
  ) {
    super(message);
    this.name = "WatchError";
  }
}

function encodeFrame(payload: string): Buffer {
  const body = Buffer.from(payload, "utf8");
  if (body.length > REQUEST_MAX) throw new WatchError("BUNDLE_LIMIT", "request over 1 MiB");
  const head = Buffer.alloc(4);
  head.writeUInt32BE(body.length);
  return Buffer.concat([head, body]);
}

async function readFrame(sock: Socket): Promise<Buffer> {
  const head = await readExact(sock, 4);
  const n = head.readUInt32BE();
  if (n < 1 || n > REPLY_MAX) throw new WatchError("BAD_FRAME", "reply frame out of bounds");
  return readExact(sock, n);
}

function readExact(sock: Socket, n: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let got = 0;
    const onData = (c: Buffer) => {
      chunks.push(c);
      got += c.length;
      if (got >= n) {
        sock.off("data", onData);
        sock.off("error", onErr);
        resolve(Buffer.concat(chunks).subarray(0, n));
      }
    };
    const onErr = (e: Error) => {
      sock.off("data", onData);
      reject(e);
    };
    sock.on("data", onData);
    sock.on("error", onErr);
  });
}

/** Canonicalize (RFC 8785 subset matching the daemon's JCS writer). */
export function jcs(v: unknown): string {
  if (v === null) return "null";
  if (typeof v === "boolean") return v ? "true" : "false";
  if (typeof v === "number") {
    if (!Number.isSafeInteger(v)) throw new WatchError("SCHEMA_INVALID", "non-safe-integer number");
    return String(v);
  }
  if (typeof v === "string") return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(jcs).join(",")}]`;
  if (typeof v === "object") {
    const entries = Object.entries(v as Record<string, unknown>)
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
    return `{${entries.map(([k, x]) => `${JSON.stringify(k)}:${jcs(x)}`).join(",")}}`;
  }
  throw new WatchError("SCHEMA_INVALID", "unsupported value");
}

/** A single-use-per-request client bound to the control socket. */
export class Watch {
  constructor(public socketPath = "/run/lattice-watch/control.sock") {}

  /** One request → one reply. Sequential calls on one connection are legal. */
  async call<T = unknown>(method: string, params: unknown = {}, id?: string): Promise<Reply<T>> {
    const reqId = id ?? `sdk-${randomUUID()}`;
    const frame = encodeFrame(jcs({ v: 1, id: reqId, method, params }));
    const sock = createConnection(this.socketPath);
    await new Promise<void>((resolve, reject) => {
      sock.once("connect", resolve);
      sock.once("error", reject);
    });
    try {
      sock.write(frame);
      const raw = await readFrame(sock);
      const rep = JSON.parse(raw.toString("utf8")) as Reply<T>;
      return rep;
    } finally {
      sock.destroy();
    }
  }

  /** Call and throw WatchError on failure replies. */
  async must<T = unknown>(method: string, params: unknown = {}, id?: string): Promise<T> {
    const rep = await this.call<T>(method, params, id);
    if (!rep.ok) {
      const e = rep.error!;
      throw new WatchError(e.code, e.message, e.retryable, e.retry_after_ms);
    }
    return rep.result as T;
  }

  async status() {
    return this.must("system.status");
  }
}

export default Watch;
