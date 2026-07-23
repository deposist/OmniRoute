// build/base-shim.ts
var BaseExecutor = class {
  constructor(provider, config) {
    this.provider = provider;
    this.config = config;
  }
  provider;
  config;
};

// ../../../../omniroute-custom-patch/upstream-v3.8.48/open-sse/executors/chatgptWebErrors.ts
var CGPT_WEB_HTTP_ERROR_MESSAGES = {
  401: "ChatGPT auth failed \u2014 session may have expired. Re-paste your __Secure-next-auth.session-token.",
  403: "ChatGPT auth failed \u2014 session may have expired. Re-paste your __Secure-next-auth.session-token.",
  404: "ChatGPT returned 404 \u2014 usually the model is no longer available on this account or the chat-requirements-token expired. Retry will start a fresh conversation.",
  413: "ChatGPT returned 413 \u2014 the request payload is too large for ChatGPT web's size limit (often hit by agentic clients like Cline/Kilo that send big system prompts and file context). Reduce the context: enable compression, trim the conversation/files, or use a smaller request.",
  429: "ChatGPT rate limited. Wait a moment and retry."
};
function describeChatGptWebHttpError(status) {
  return CGPT_WEB_HTTP_ERROR_MESSAGES[status] ?? `ChatGPT returned HTTP ${status}`;
}

// build/tool-shim.ts
function prepareToolMessages(_body, messages) {
  return { hasTools: false, requestedTools: void 0, effectiveMessages: messages };
}
async function buildToolModeResponse(response) {
  return response;
}

// ../../../../omniroute-custom-patch/upstream-v3.8.48/open-sse/executors/chatgpt-web.ts
import { createHash as createHash3, randomUUID as randomUUID3, randomBytes } from "node:crypto";

// ../../../../omniroute-custom-patch/upstream-v3.8.48/open-sse/utils/sha3-512.ts
import { createHash } from "node:crypto";
var MASK = (1n << 64n) - 1n;
var RC = [
  0x0000000000000001n,
  0x0000000000008082n,
  0x800000000000808an,
  0x8000000080008000n,
  0x000000000000808bn,
  0x0000000080000001n,
  0x8000000080008081n,
  0x8000000000008009n,
  0x000000000000008an,
  0x0000000000000088n,
  0x0000000080008009n,
  0x000000008000000an,
  0x000000008000808bn,
  0x800000000000008bn,
  0x8000000000008089n,
  0x8000000000008003n,
  0x8000000000008002n,
  0x8000000000000080n,
  0x000000000000800an,
  0x800000008000000an,
  0x8000000080008081n,
  0x8000000000008080n,
  0x0000000080000001n,
  0x8000000080008008n
];
var ROT = [
  0,
  1,
  62,
  28,
  27,
  36,
  44,
  6,
  55,
  20,
  3,
  10,
  43,
  25,
  39,
  41,
  45,
  15,
  21,
  8,
  18,
  2,
  61,
  56,
  14
];
function rotl64(x, n) {
  if (n === 0) return x;
  const bn = BigInt(n);
  return (x << bn | x >> 64n - bn) & MASK;
}
function keccakF1600(s) {
  const C = new Array(5);
  const D = new Array(5);
  const B = new Array(25);
  for (let round = 0; round < 24; round++) {
    for (let x = 0; x < 5; x++) C[x] = s[x] ^ s[x + 5] ^ s[x + 10] ^ s[x + 15] ^ s[x + 20];
    for (let x = 0; x < 5; x++) D[x] = C[(x + 4) % 5] ^ rotl64(C[(x + 1) % 5], 1);
    for (let x = 0; x < 5; x++) for (let y = 0; y < 5; y++) s[x + 5 * y] ^= D[x];
    for (let x = 0; x < 5; x++) {
      for (let y = 0; y < 5; y++) {
        B[y + 5 * ((2 * x + 3 * y) % 5)] = rotl64(s[x + 5 * y], ROT[x + 5 * y]);
      }
    }
    for (let x = 0; x < 5; x++) {
      for (let y = 0; y < 5; y++) {
        s[x + 5 * y] = B[x + 5 * y] ^ ~B[(x + 1) % 5 + 5 * y] & MASK & B[(x + 2) % 5 + 5 * y];
      }
    }
    s[0] ^= RC[round];
  }
}
var RATE_BYTES = 72;
function sha3_512Bytes(msg) {
  const s = new Array(25).fill(0n);
  const padLen = RATE_BYTES - msg.length % RATE_BYTES;
  const padded = new Uint8Array(msg.length + padLen);
  padded.set(msg);
  padded[msg.length] = 6;
  padded[padded.length - 1] |= 128;
  for (let off = 0; off < padded.length; off += RATE_BYTES) {
    for (let i = 0; i < RATE_BYTES / 8; i++) {
      let lane = 0n;
      for (let b = 0; b < 8; b++) lane |= BigInt(padded[off + i * 8 + b]) << BigInt(8 * b);
      s[i] ^= lane;
    }
    keccakF1600(s);
  }
  const out = new Uint8Array(64);
  for (let i = 0; i < 8; i++) {
    const lane = s[i];
    for (let b = 0; b < 8; b++) out[i * 8 + b] = Number(lane >> BigInt(8 * b) & 0xffn);
  }
  return out;
}
function toBytes(input) {
  return typeof input === "string" ? new Uint8Array(Buffer.from(input, "utf8")) : input;
}
function sha3_512HexJs(input) {
  return Buffer.from(sha3_512Bytes(toBytes(input))).toString("hex");
}
var nativeHasher;
function detectNative() {
  try {
    createHash("sha3-512").update(Buffer.alloc(0)).digest("hex");
    return (data) => createHash("sha3-512").update(data).digest("hex");
  } catch {
    return null;
  }
}
function sha3_512Hex(input) {
  const data = toBytes(input);
  if (nativeHasher === void 0) nativeHasher = detectNative();
  if (nativeHasher) {
    try {
      return nativeHasher(data);
    } catch {
      nativeHasher = null;
    }
  }
  return sha3_512HexJs(data);
}

// ../../../../omniroute-custom-patch/upstream-v3.8.48/open-sse/services/chatgptTlsClient.ts
import { tmpdir } from "node:os";
import { join } from "node:path";
import { mkdtemp, open, unlink, rmdir, stat, readFile } from "node:fs/promises";
import { randomUUID } from "node:crypto";

// build/proxy-shim.ts
import { ProxyAgent, WebSocket as UndiciWebSocket, fetch as undiciFetch } from "undici";
import { socksDispatcher } from "fetch-socks";
var pluginProxyUrl = null;
var originalFetch = globalThis.fetch.bind(globalThis);
var originalWebSocket = globalThis.WebSocket;
function dispatcherFor(proxyUrl) {
  const parsed = new URL(proxyUrl);
  if (parsed.protocol === "socks5:") {
    return socksDispatcher({
      type: 5,
      host: parsed.hostname,
      port: Number(parsed.port || 1080),
      ...parsed.username ? { userId: decodeURIComponent(parsed.username) } : {},
      ...parsed.password ? { password: decodeURIComponent(parsed.password) } : {}
    });
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error(`Unsupported plugin proxy protocol: ${parsed.protocol}`);
  }
  return new ProxyAgent(proxyUrl);
}
function installNetworkAdapters() {
  globalThis.fetch = (async (input, init = {}) => {
    if (!pluginProxyUrl) return originalFetch(input, init);
    return undiciFetch(input, {
      ...init,
      dispatcher: dispatcherFor(pluginProxyUrl)
    });
  });
  globalThis.WebSocket = function PluginProxyWebSocket(url, protocols) {
    if (!pluginProxyUrl) return new originalWebSocket(url, protocols);
    return new UndiciWebSocket(url, {
      ...protocols ? { protocols } : {},
      dispatcher: dispatcherFor(pluginProxyUrl)
    });
  };
}
function setPluginProxyUrl(value) {
  pluginProxyUrl = value;
  installNetworkAdapters();
}
function resolveProxyForRequest(_targetUrl) {
  return pluginProxyUrl ? { source: "plugin-context", proxyUrl: pluginProxyUrl } : { source: "direct", proxyUrl: null };
}

// ../../../../omniroute-custom-patch/upstream-v3.8.48/open-sse/services/tlsClientProxy.ts
function resolveTlsClientProxyUrl(targetUrl, perCall, resolveProxyForRequest2) {
  if (perCall && perCall.length > 0) return perCall;
  let info;
  try {
    info = resolveProxyForRequest2(targetUrl);
  } catch (err) {
    throw new Error(
      `[TlsClient] Proxy resolution failed for ${targetUrl}; refusing direct connection (fail-closed): ${err instanceof Error ? err.message : String(err)}`
    );
  }
  return info && info.proxyUrl ? info.proxyUrl : void 0;
}

// ../../../../omniroute-custom-patch/upstream-v3.8.48/open-sse/services/chatgptTlsClient.ts
var clientPromise = null;
var exitHookInstalled = false;
var CHATGPT_PROFILE = "firefox_148";
var DEFAULT_TIMEOUT_MS = Number.parseInt(process.env.OMNIROUTE_CHATGPT_TLS_TIMEOUT_MS || "", 10) || 6e4;
var HARD_TIMEOUT_GRACE_MS = Number.parseInt(process.env.OMNIROUTE_CHATGPT_TLS_GRACE_MS || "", 10) || 1e4;
var STREAM_FIRST_BYTE_TIMEOUT_MS = Number.parseInt(process.env.OMNIROUTE_CHATGPT_STREAM_FIRST_BYTE_TIMEOUT_MS || "", 10) || 3e4;
function installExitHook() {
  if (exitHookInstalled) return;
  exitHookInstalled = true;
  const stop = async () => {
    if (!clientPromise) return;
    try {
      const c = await clientPromise;
      await c.stop?.();
    } catch {
    }
  };
  process.once("beforeExit", stop);
  process.once("SIGINT", () => {
    void stop();
  });
  process.once("SIGTERM", () => {
    void stop();
  });
}
function resetClientCache() {
  clientPromise = null;
}
var TlsClientHangError = class extends Error {
  constructor(message) {
    super(message);
    this.name = "TlsClientHangError";
  }
};
async function raceWithTimeout(promise, timeoutMs, signal) {
  let timer = null;
  let abortListener = null;
  try {
    const racers = [
      promise,
      new Promise((_, reject) => {
        timer = setTimeout(() => {
          reject(
            new TlsClientHangError(
              `tls-client-node call exceeded ${timeoutMs}ms \u2014 native binding likely deadlocked`
            )
          );
        }, timeoutMs);
      })
    ];
    if (signal) {
      racers.push(
        new Promise((_, reject) => {
          if (signal.aborted) {
            reject(makeAbortError(signal));
            return;
          }
          abortListener = () => reject(makeAbortError(signal));
          signal.addEventListener("abort", abortListener, { once: true });
        })
      );
    }
    return await Promise.race(racers);
  } finally {
    if (timer) clearTimeout(timer);
    if (signal && abortListener) signal.removeEventListener("abort", abortListener);
  }
}
async function getClient() {
  if (!clientPromise) {
    clientPromise = (async () => {
      try {
        const mod = await import("tls-client-node");
        const TLSClient = mod.TLSClient;
        const client = new TLSClient({ runtimeMode: "native" });
        await client.start();
        installExitHook();
        return client;
      } catch (err) {
        clientPromise = null;
        const msg = err instanceof Error ? err.message : String(err);
        throw new TlsClientUnavailableError(
          `TLS impersonation client failed to start: ${msg}. Verify tls-client-node is installed and its native binary downloaded.`
        );
      }
    })();
  }
  return clientPromise;
}
var TlsClientUnavailableError = class extends Error {
  constructor(message) {
    super(message);
    this.name = "TlsClientUnavailableError";
  }
};
function resolveProxyUrl(perCall) {
  return resolveTlsClientProxyUrl("https://chatgpt.com", perCall, resolveProxyForRequest);
}
var testOverride = null;
async function tlsFetchChatGpt(url, options = {}) {
  if (testOverride) return testOverride(url, options);
  if (options.signal?.aborted) {
    throw makeAbortError(options.signal);
  }
  const client = await getClient();
  if (options.signal?.aborted) {
    throw makeAbortError(options.signal);
  }
  const requestOptions = {
    method: options.method || "GET",
    headers: options.headers || {},
    body: options.body,
    tlsClientIdentifier: CHATGPT_PROFILE,
    timeoutMilliseconds: options.timeoutMs ?? DEFAULT_TIMEOUT_MS,
    followRedirects: true,
    withRandomTLSExtensionOrder: true,
    isByteResponse: options.byteResponse === true,
    // Plumb the configured proxy through to the native binding. tls-client-node
    // consults `proxyUrl` in the per-call options (it does NOT auto-pick up
    // HTTP_PROXY / HTTPS_PROXY env), so callers / env have to be threaded in
    // explicitly. See `resolveProxyUrl()` for the lookup order. Without this
    // line, every chatgpt-web call egresses with the bare host IP regardless
    // of dashboard proxy config — see #2022.
    proxyUrl: resolveProxyUrl(options.proxyUrl)
  };
  if (options.stream) {
    return await tlsFetchStreaming(
      client,
      url,
      requestOptions,
      options.streamEofSymbol,
      options.signal ?? null,
      (options.timeoutMs ?? DEFAULT_TIMEOUT_MS) + HARD_TIMEOUT_GRACE_MS,
      STREAM_FIRST_BYTE_TIMEOUT_MS
    );
  }
  let tlsResponse;
  try {
    tlsResponse = await raceWithTimeout(
      client.request(url, requestOptions),
      (options.timeoutMs ?? DEFAULT_TIMEOUT_MS) + HARD_TIMEOUT_GRACE_MS,
      options.signal ?? null
    );
  } catch (err) {
    if (err instanceof TlsClientHangError) {
      resetClientCache();
    }
    throw err;
  }
  if (options.signal?.aborted) {
    throw makeAbortError(options.signal);
  }
  return {
    status: tlsResponse.status,
    headers: toHeaders(tlsResponse.headers),
    text: tlsResponse.body,
    body: null
  };
}
function makeAbortError(signal) {
  const reason = signal.reason;
  if (reason instanceof Error) return reason;
  const err = new Error(typeof reason === "string" ? reason : "The operation was aborted");
  err.name = "AbortError";
  return err;
}
function toHeaders(raw) {
  const h = new Headers();
  for (const [k, vs] of Object.entries(raw || {})) {
    for (const v of vs) h.append(k, v);
  }
  return h;
}
async function tlsFetchStreaming(client, url, requestOptions, eofSymbol = "[DONE]", signal = null, hardTimeoutMs = DEFAULT_TIMEOUT_MS + HARD_TIMEOUT_GRACE_MS, firstByteTimeoutMs = STREAM_FIRST_BYTE_TIMEOUT_MS) {
  const dir = await mkdtemp(join(tmpdir(), "cgpt-stream-"));
  const path = join(dir, `${randomUUID()}.sse`);
  const streamOpts = {
    ...requestOptions,
    streamOutputPath: path,
    streamOutputBlockSize: 1024,
    streamOutputEOFSymbol: eofSymbol
  };
  let resetOnHang = true;
  const requestPromise = raceWithTimeout(
    client.request(url, streamOpts),
    hardTimeoutMs,
    signal
  ).catch((err) => {
    if (resetOnHang && err instanceof TlsClientHangError) {
      resetClientCache();
      resetOnHang = false;
    }
    throw err;
  });
  const ready = await waitForContent(path, firstByteTimeoutMs, requestPromise);
  if (!ready) {
    const r = await requestPromise.catch(
      (e) => ({ status: 502, headers: {}, body: String(e) })
    );
    const fileText = await readTextFileIfExists(path);
    await cleanupTempPath(path);
    return {
      status: r.status,
      headers: toHeaders(r.headers),
      text: fileText || r.body,
      body: null
    };
  }
  const peek = await readFirstBytes(path, 256);
  if (!looksLikeSse(peek)) {
    const r = await requestPromise.catch(
      (e) => ({ status: 502, headers: {}, body: String(e) })
    );
    const fileText = await readTextFileIfExists(path);
    await cleanupTempPath(path);
    return {
      status: r.status,
      headers: toHeaders(r.headers),
      text: r.body || fileText,
      body: null
    };
  }
  const stream = tailFile(path, eofSymbol, requestPromise, signal);
  const headers = new Headers({
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-cache"
  });
  return { status: 200, headers, text: null, body: stream };
}
function looksLikeSse(text) {
  const trimmed = text.replace(/^[\s\r\n]+/, "");
  if (!trimmed) return false;
  if (trimmed.startsWith(":")) return true;
  return /^(data|event|id|retry):/i.test(trimmed);
}
async function cleanupTempPath(path) {
  await unlink(path).catch(() => {
  });
  const dir = path.substring(0, path.lastIndexOf("/"));
  await rmdir(dir).catch(() => {
  });
}
async function readTextFileIfExists(path) {
  try {
    return await readFile(path, "utf8");
  } catch {
    return "";
  }
}
async function readFirstBytes(path, n) {
  const fd = await open(path, "r");
  try {
    const buf = Buffer.alloc(n);
    const { bytesRead } = await fd.read(buf, 0, n, 0);
    return buf.subarray(0, bytesRead).toString("utf8");
  } finally {
    await fd.close().catch(() => {
    });
  }
}
async function waitForContent(path, timeoutMs, requestPromise) {
  let requestSettled = false;
  requestPromise.then(
    () => {
      requestSettled = true;
    },
    () => {
      requestSettled = true;
    }
  );
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      const s = await stat(path);
      if (s.size > 0) return true;
    } catch {
    }
    if (requestSettled) return false;
    await sleep(25);
  }
  return false;
}
function tailFile(path, eofSymbol, done, signal = null) {
  return new ReadableStream({
    async start(controller) {
      const fd = await open(path, "r");
      const buf = Buffer.alloc(64 * 1024);
      let offset = 0;
      let finished = false;
      let aborted = false;
      let upstreamError = null;
      done.then(
        () => {
          finished = true;
        },
        (err) => {
          upstreamError = err instanceof Error ? err : new Error(String(err));
          finished = true;
        }
      );
      const onAbort = () => {
        aborted = true;
      };
      if (signal) {
        if (signal.aborted) aborted = true;
        else signal.addEventListener("abort", onAbort, { once: true });
      }
      let errored = false;
      try {
        while (!aborted) {
          const { bytesRead } = await fd.read(buf, 0, buf.length, offset);
          if (bytesRead > 0) {
            const chunk = buf.subarray(0, bytesRead);
            offset += bytesRead;
            const text = chunk.toString("utf8");
            if (text.includes(eofSymbol)) {
              const cutAt = text.indexOf(eofSymbol) + eofSymbol.length;
              controller.enqueue(new Uint8Array(chunk.subarray(0, cutAt)));
              break;
            }
            controller.enqueue(new Uint8Array(chunk));
          } else if (finished) {
            if (upstreamError) {
              controller.error(upstreamError);
              errored = true;
            }
            break;
          } else {
            await sleep(25);
          }
        }
      } catch (err) {
        controller.error(err);
        errored = true;
      } finally {
        if (signal) signal.removeEventListener("abort", onAbort);
        await fd.close().catch(() => {
        });
        await unlink(path).catch(() => {
        });
        const dir = path.substring(0, path.lastIndexOf("/"));
        await rmdir(dir).catch(() => {
        });
        if (!errored) controller.close();
      }
    }
  });
}
function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

// build/image-cache.ts
import { createHash as createHash2, randomUUID as randomUUID2 } from "node:crypto";
var cache = /* @__PURE__ */ new Map();
var TTL_MS = 30 * 6e4;
var MAX_ENTRIES = 25;
function purge() {
  const now = Date.now();
  for (const [id, entry] of cache) if (entry.expiresAt <= now) cache.delete(id);
  while (cache.size >= MAX_ENTRIES) {
    const oldest = cache.keys().next().value;
    if (!oldest) break;
    cache.delete(oldest);
  }
}
function storeChatGptImage(bytes, mime, ttlMs = TTL_MS, context) {
  purge();
  const id = randomUUID2().replace(/-/g, "");
  cache.set(id, {
    bytes,
    mime,
    expiresAt: Date.now() + ttlMs,
    context,
    bytesSha256: createHash2("sha256").update(bytes).digest("hex")
  });
  return id;
}
function getChatGptImage(id) {
  purge();
  return cache.get(id) ?? null;
}
function getChatGptImageConversationContext(id) {
  return getChatGptImage(id)?.context ?? null;
}

// ../../../../omniroute-custom-patch/upstream-v3.8.48/open-sse/executors/chatgpt-web/models.ts
var MODEL_MAP = {
  // ChatGPT backend slugs are also accepted directly for power users / tests.
  "gpt-5-6-pro": "gpt-5-6-pro",
  "gpt-5-6-thinking": "gpt-5-6-thinking",
  "gpt-5-5-pro": "gpt-5-5-pro",
  "gpt-5-5-pro-extended": "gpt-5-5-pro",
  "gpt-5-5-thinking": "gpt-5-5-thinking",
  "gpt-5-5": "gpt-5-5",
  "gpt-5-3": "gpt-5-3",
  "gpt-5-3-mini": "gpt-5-3-mini",
  // Public OmniRoute dot-form ids exposed by the provider catalog.
  "gpt-5.6-pro": "gpt-5-6-pro",
  "gpt-5.6-thinking": "gpt-5-6-thinking",
  "gpt-5.5-pro": "gpt-5-5-pro",
  "gpt-5.5-pro-extended": "gpt-5-5-pro",
  "gpt-5.5-thinking": "gpt-5-5-thinking",
  "gpt-5.5": "gpt-5-5",
  "gpt-5.3-instant": "gpt-5-3-instant",
  "gpt-5.3": "gpt-5-3",
  "gpt-5.3-mini": "gpt-5-3-mini",
  o3: "o3"
};
var MODEL_FORCED_EFFORT = {
  "gpt-5-6-pro": "standard",
  "gpt-5.6-pro": "standard",
  "gpt-5-5-pro": "standard",
  "gpt-5-5-pro-extended": "extended",
  "gpt-5.5-pro": "standard",
  "gpt-5.5-pro-extended": "extended"
};
var THINKING_CAPABLE_SLUGS = new Set(
  Object.entries(MODEL_MAP).filter(([k]) => k.includes("thinking") || k === "o3").map(([, v]) => v)
);
function isThinkingCapableModel(modelId, slug) {
  return modelId.includes("thinking") || modelId === "o3" || slug.includes("thinking") || THINKING_CAPABLE_SLUGS.has(slug) || THINKING_CAPABLE_SLUGS.has(modelId);
}
function normalizeThinkingEffort(input) {
  if (typeof input !== "string") return null;
  const v = input.trim().toLowerCase();
  if (v === "extended" || v === "high" || v === "xhigh") return "extended";
  if (v === "standard" || v === "low" || v === "medium" || v === "minimal") {
    return "standard";
  }
  return null;
}
function resolveThinkingEffort(body, providerSpecificData) {
  if (providerSpecificData && providerSpecificData.thinkingEffort !== void 0) {
    return normalizeThinkingEffort(providerSpecificData.thinkingEffort);
  }
  const b = body ?? null;
  if (!b) return null;
  const top = normalizeThinkingEffort(b.reasoning_effort);
  if (top) return top;
  const nested = b.reasoning?.effort;
  return normalizeThinkingEffort(nested);
}
function resolveChatGptModel(model, body, providerSpecificData) {
  const slug = MODEL_MAP[model] ?? model;
  const forcedEffort = MODEL_FORCED_EFFORT[model] ?? null;
  const effort = forcedEffort ?? resolveThinkingEffort(body, providerSpecificData);
  const isPro = slug === "gpt-5-6-pro" || slug === "gpt-5-5-pro";
  return { slug, effort, isPro };
}

// ../../../../omniroute-custom-patch/upstream-v3.8.48/open-sse/executors/chatgpt-web/citations.ts
var ENTITY_RE = /entity\["[^"]*","([^"]*)"[^\]]*\]/g;
var CHATGPT_MARKER_START = "\uE200";
var CHATGPT_MARKER_SEP = "\uE202";
var CHATGPT_MARKER_END = "\uE201";
var CHATGPT_REF_TOKEN_RE = /turn\d+(?:search|product|news|image|webpage)\d+/g;
function asRecord(value) {
  return value && typeof value === "object" ? value : null;
}
function asString(value) {
  return typeof value === "string" && value.trim() ? value : null;
}
function asNumber(value) {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}
function asArray(value) {
  return Array.isArray(value) ? value : [];
}
function markdownLinkText(value) {
  return value.replace(/\\/g, "\\\\").replace(/\[/g, "\\[").replace(/\]/g, "\\]").replace(/\n/g, " ").trim();
}
function markdownUrl(value) {
  return value.replace(/\(/g, "%28").replace(/\)/g, "%29");
}
function canonicalCitationUrl(value) {
  try {
    const url = new URL(value);
    url.searchParams.delete("utm_source");
    return url.toString();
  } catch {
    return value;
  }
}
function referenceUrls(ref) {
  const urls = [];
  for (const key of ["url", "safe_url", "link"]) {
    const url = asString(ref[key]);
    if (url) urls.push(url);
  }
  for (const url of asArray(ref.safe_urls)) {
    if (typeof url === "string" && url.trim()) urls.push(url);
  }
  return [...new Set(urls)];
}
function refTokenFromStructuredRef(ref) {
  const turn = asNumber(ref.turn_index);
  const refType = asString(ref.ref_type);
  const refIndex = asNumber(ref.ref_index);
  if (turn == null || refIndex == null || !refType) return null;
  return `turn${turn}${refType}${refIndex}`;
}
function mapStructuredRefs(refs, sourceNumber, refTokenToSourceNumber) {
  for (const refValue of asArray(refs)) {
    const ref = asRecord(refValue);
    if (!ref) continue;
    const token = refTokenFromStructuredRef(ref);
    if (token && !refTokenToSourceNumber.has(token)) {
      refTokenToSourceNumber.set(token, sourceNumber);
    }
  }
}
function formatCitationLinks(numbers, sources) {
  return [...new Set(numbers)].sort((a, b) => a - b).map((num) => {
    const source = sources[num - 1];
    return source ? `[${num}](${markdownUrl(source.url)})` : "";
  }).filter(Boolean).join("");
}
function urlMarkerLabel(markerText) {
  if (!markerText) return null;
  const privateMatch = markerText.match(/\uE200url\uE202([^\uE201\uE202]+)/u);
  if (privateMatch?.[1]) return privateMatch[1].trim();
  const plainMatch = markerText.match(/^url[:\s]+(.+)$/i);
  return plainMatch?.[1]?.trim() || null;
}
function citationMarkerCandidates(markerText) {
  if (!markerText) return [];
  const candidates = [markerText];
  const tokens = markerText.match(CHATGPT_REF_TOKEN_RE) ?? [];
  if (tokens.length > 0 && markerText.includes("cite")) {
    candidates.push(
      `${CHATGPT_MARKER_START}cite${tokens.map((token) => CHATGPT_MARKER_SEP + token).join("")}${CHATGPT_MARKER_END}`
    );
  }
  return [...new Set(candidates)];
}
function collectSupportingWebsiteNumbers(item, addSource, refTokenToSourceNumber) {
  const numbers = [];
  for (const supportingValue of asArray(item.supporting_websites)) {
    const supporting = asRecord(supportingValue);
    if (!supporting) continue;
    const supportingNumber = addSource(supporting.title, supporting.url, supporting.attribution);
    if (supportingNumber) {
      numbers.push(supportingNumber);
      mapStructuredRefs(supporting.refs, supportingNumber, refTokenToSourceNumber);
    }
  }
  return numbers;
}
function collectGroupedWebpageItemNumbers(itemValue, addSource, refTokenToSourceNumber) {
  const item = asRecord(itemValue);
  if (!item) return [];
  const numbers = [];
  const mainNumber = addSource(item.title, item.url, item.attribution);
  if (mainNumber) {
    numbers.push(mainNumber);
    mapStructuredRefs(item.refs, mainNumber, refTokenToSourceNumber);
  }
  numbers.push(...collectSupportingWebsiteNumbers(item, addSource, refTokenToSourceNumber));
  return numbers;
}
function collectGroupedWebpagesFallbackNumbers(ref, addSource) {
  const numbers = [];
  for (const url of referenceUrls(ref)) {
    const fallbackNumber = addSource(ref.title, url, ref.attribution);
    if (fallbackNumber) numbers.push(fallbackNumber);
  }
  return numbers;
}
function collectGroupedWebpagesRef(ref, sources, addSource, addMention, refTokenToSourceNumber) {
  let numbers = [];
  for (const itemValue of asArray(ref.items)) {
    numbers.push(...collectGroupedWebpageItemNumbers(itemValue, addSource, refTokenToSourceNumber));
  }
  if (numbers.length === 0) {
    numbers = collectGroupedWebpagesFallbackNumbers(ref, addSource);
  }
  addMention(ref, formatCitationLinks(numbers, sources));
}
function collectSourcesFootnoteRef(ref, addSource) {
  for (const sourceValue of asArray(ref.sources)) {
    const source = asRecord(sourceValue);
    if (source) addSource(source.title, source.url, source.attribution);
  }
}
function collectDefaultRef(ref, type, sources, addSource, addMention, refTokenToSourceNumber) {
  const urls = referenceUrls(ref);
  const label = urlMarkerLabel(asString(ref.matched_text));
  if ((type === "webpage" || type === "url") && label && urls[0]) {
    addMention(ref, `[${markdownLinkText(label)}](${markdownUrl(urls[0])})`);
    return;
  }
  const numbers = urls.map((url) => addSource(ref.title ?? ref.alt, url, ref.attribution)).filter((num) => num > 0);
  if (numbers.length === 0) return;
  mapStructuredRefs(ref.refs, numbers[0], refTokenToSourceNumber);
  addMention(ref, formatCitationLinks(numbers, sources));
}
function collectChatGptCitationData(metadata) {
  const refs = asArray(metadata?.content_references);
  const sources = [];
  const mentions = [];
  const sourceIndexByCanonicalUrl = /* @__PURE__ */ new Map();
  const refTokenToSourceNumber = /* @__PURE__ */ new Map();
  const addSource = (titleValue, urlValue, attributionValue) => {
    const url = asString(urlValue);
    if (!url) return 0;
    const canonical = canonicalCitationUrl(url);
    const existing = sourceIndexByCanonicalUrl.get(canonical);
    if (existing) return existing;
    const title = asString(titleValue) ?? url;
    const attribution = asString(attributionValue) ?? "";
    const idx = sources.length + 1;
    sources.push({ title: title.replace(/\n/g, " ").trim(), url, attribution });
    sourceIndexByCanonicalUrl.set(canonical, idx);
    return idx;
  };
  const addMention = (ref, replacement) => {
    if (!replacement) return;
    const start = asNumber(ref.start_idx);
    const end = asNumber(ref.end_idx);
    const markerText = asString(ref.matched_text) ?? void 0;
    if (markerText || start != null && end != null) {
      mentions.push({
        ...start != null ? { start } : {},
        ...end != null ? { end } : {},
        ...markerText ? { markerText } : {},
        replacement
      });
    }
  };
  for (const refValue of refs) {
    const ref = asRecord(refValue);
    if (!ref) continue;
    const type = asString(ref.type) ?? "";
    if (type === "grouped_webpages") {
      collectGroupedWebpagesRef(ref, sources, addSource, addMention, refTokenToSourceNumber);
      continue;
    }
    if (type === "sources_footnote") {
      collectSourcesFootnoteRef(ref, addSource);
      continue;
    }
    collectDefaultRef(ref, type, sources, addSource, addMention, refTokenToSourceNumber);
  }
  return { sources, mentions, refTokenToSourceNumber };
}
function replacePrivateCitationMarkers(text, citationData) {
  const replaceTokens = (tokens) => {
    const numbers = tokens.map((token) => citationData.refTokenToSourceNumber.get(token)).filter((num) => typeof num === "number");
    return numbers.length > 0 ? formatCitationLinks(numbers, citationData.sources) : "";
  };
  return text.replace(/\uE200cite((?:\uE202[^\uE201\uE202]+)+)\uE201/gu, (_all, body) => {
    const tokens = [...body.matchAll(/\uE202([^\uE201\uE202]+)/gu)].map((match) => match[1]);
    return replaceTokens(tokens);
  }).replace(
    /\bcite((?:turn\d+(?:search|product|news|image|webpage)\d+)+)\b/g,
    (_all, body) => {
      return replaceTokens(body.match(CHATGPT_REF_TOKEN_RE) ?? []);
    }
  );
}
function stripDanglingChatGptMarkers(text, citationData) {
  return replacePrivateCitationMarkers(text, citationData).replace(
    /\uE200url\uE202([^\uE201\uE202]+)\uE202(https?:\/\/[^\uE201]+)\uE201/gu,
    (_all, label, url) => {
      return `[${markdownLinkText(label)}](${markdownUrl(url)})`;
    }
  ).replace(
    /\uE200url\uE202([^\uE201\uE202]+)\uE202(?:[^\uE201]*\uE201)?/gu,
    (_all, label) => {
      return label.trim();
    }
  ).replace(/\uE200cite(?:\uE202[^\uE201\uE202]*)*$/gu, "").replace(/\uE200[a-z_]+(?:\uE202[^\uE201\uE202]*)*\uE201/giu, "").replace(/\uE200[a-z_]+(?:\uE202[^\uE201\uE202]*)*$/giu, "").replace(/\uE202?turn\d+(?:search|product|news|image|webpage)\d+\uE201?/gu, "").replace(/[\uE200\uE201\uE202]/gu, "");
}
function applyChatGptCitations(text, metadata) {
  const citationData = collectChatGptCitationData(metadata);
  let rendered = text;
  for (const mention of [...citationData.mentions].sort(
    (a, b) => (b.start ?? -1) - (a.start ?? -1)
  )) {
    let replaced = false;
    for (const markerText of citationMarkerCandidates(mention.markerText)) {
      const limit = mention.start != null ? Math.min(rendered.length, mention.start + markerText.length) : rendered.length;
      let pos = rendered.lastIndexOf(markerText, limit);
      if (pos < 0) pos = rendered.indexOf(markerText);
      if (pos >= 0) {
        rendered = rendered.slice(0, pos) + mention.replacement + rendered.slice(pos + markerText.length);
        replaced = true;
        break;
      }
    }
    if (!replaced && mention.start != null && mention.end != null) {
      const start = Math.max(0, Math.min(mention.start, rendered.length));
      const end = Math.max(start, Math.min(mention.end, rendered.length));
      rendered = rendered.slice(0, start) + mention.replacement + rendered.slice(end);
    }
  }
  return stripDanglingChatGptMarkers(rendered, citationData);
}
function cleanChatGptText(text, metadata) {
  return applyChatGptCitations(text.replace(ENTITY_RE, "$1"), metadata);
}

// ../../../../omniroute-custom-patch/upstream-v3.8.48/open-sse/executors/chatgpt-web/handoff.ts
var CONVERSATION_RESUME_URL = "https://chatgpt.com/backend-api/f/conversation/resume";
var RESUME_OFFSETS = [0, 1, 2];
function stringToStream(text) {
  const bytes = new TextEncoder().encode(text);
  return new ReadableStream({
    start(controller) {
      controller.enqueue(bytes);
      controller.close();
    }
  });
}
async function readFinalAssistantAnswer(eventStream, signal, readContent) {
  let text = "";
  let messageId;
  let metadata;
  for await (const chunk of readContent(eventStream, signal)) {
    if (chunk.error) return null;
    if (chunk.answer) text = chunk.answer;
    if (chunk.messageId) messageId = chunk.messageId;
    if (chunk.metadata) metadata = chunk.metadata;
  }
  if (!text.trim()) return null;
  return { text, messageId, metadata, finished: true };
}
async function attemptResumeOffset({
  conversationId,
  offset,
  resumeHeaders,
  timeoutMs,
  signal,
  log,
  readContent
}) {
  try {
    const response = await tlsFetchChatGpt(CONVERSATION_RESUME_URL, {
      method: "POST",
      headers: resumeHeaders,
      body: JSON.stringify({ conversation_id: conversationId, offset }),
      timeoutMs,
      signal,
      stream: true
    });
    if (response.status === 404) return { answer: null, shouldRetry: true };
    if (response.status >= 400) {
      log?.warn?.(
        "CGPT-WEB",
        `conversation resume ${response.status}: ${(response.text || "").slice(0, 300)}`
      );
      return { answer: null, shouldRetry: false };
    }
    const eventStream = response.body ?? (response.text ? stringToStream(response.text) : null);
    if (!eventStream) return { answer: null, shouldRetry: true };
    const answer = await readFinalAssistantAnswer(eventStream, signal, readContent);
    return { answer, shouldRetry: !answer };
  } catch (error) {
    log?.warn?.(
      "CGPT-WEB",
      `conversation resume failed: ${error instanceof Error ? error.message : String(error)}`
    );
    return { answer: null, shouldRetry: false };
  }
}
async function resumeChatGptHandoff({
  conversationId,
  resumeToken,
  headers,
  timeoutMs,
  signal,
  log,
  readContent
}) {
  const resumeHeaders = {
    ...headers,
    Accept: "text/event-stream",
    "Content-Type": "application/json",
    "x-conduit-token": resumeToken,
    "X-OpenAI-Target-Path": "/backend-api/f/conversation/resume",
    "X-OpenAI-Target-Route": "/backend-api/f/conversation/resume"
  };
  for (const offset of RESUME_OFFSETS) {
    const attempt = await attemptResumeOffset({
      conversationId,
      resumeHeaders,
      offset,
      timeoutMs,
      signal,
      log,
      readContent
    });
    if (attempt.answer) return attempt.answer;
    if (!attempt.shouldRetry) return null;
  }
  log?.warn?.("CGPT-WEB", `conversation resume returned no assistant text for ${conversationId}`);
  return null;
}

// ../../../../omniroute-custom-patch/upstream-v3.8.48/open-sse/executors/chatgpt-web.ts
var CHATGPT_BASE = "https://chatgpt.com";
var SESSION_URL = `${CHATGPT_BASE}/api/auth/session`;
var SENTINEL_PREPARE_URL = `${CHATGPT_BASE}/backend-api/sentinel/chat-requirements/prepare`;
var SENTINEL_CR_URL = `${CHATGPT_BASE}/backend-api/sentinel/chat-requirements`;
var CONV_URL = `${CHATGPT_BASE}/backend-api/f/conversation`;
var USER_LAST_USED_MODEL_CONFIG_URL = `${CHATGPT_BASE}/backend-api/settings/user_last_used_model_config`;
var DEFAULT_PRO_POLL_TIMEOUT_MS = 20 * 6e4;
var DEFAULT_PRO_POLL_INTERVAL_MS = 4e3;
var CHATGPT_USER_AGENT = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:152.0) Gecko/20100101 Firefox/152.0";
var OAI_CLIENT_VERSION = "prod-81e0c5cdf6140e8c5db714d613337f4aeab94029";
var OAI_CLIENT_BUILD_NUMBER = "6128297";
var deviceIdCache = /* @__PURE__ */ new Map();
function deviceIdFor(cookie) {
  const key = cookieKey(cookie);
  let id = deviceIdCache.get(key);
  if (!id) {
    const h = createHash3("sha256").update(cookie).digest("hex");
    id = `${h.slice(0, 8)}-${h.slice(8, 12)}-4${h.slice(13, 16)}-${(parseInt(h.slice(16, 17), 16) & 3 | 8).toString(16)}${h.slice(17, 20)}-` + h.slice(20, 32);
    if (deviceIdCache.size >= 200) {
      const first = deviceIdCache.keys().next().value;
      if (first) deviceIdCache.delete(first);
    }
    deviceIdCache.set(key, id);
  }
  return id;
}
function browserHeaders() {
  return {
    Accept: "*/*",
    "Accept-Language": "en-US,en;q=0.9",
    "Cache-Control": "no-cache",
    Origin: CHATGPT_BASE,
    Pragma: "no-cache",
    Referer: `${CHATGPT_BASE}/`,
    "Sec-Fetch-Dest": "empty",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Site": "same-origin",
    "User-Agent": CHATGPT_USER_AGENT
  };
}
function oaiHeaders(sessionId, deviceId) {
  return {
    "OAI-Language": "en-US",
    "OAI-Device-Id": deviceId,
    "OAI-Client-Version": OAI_CLIENT_VERSION,
    "OAI-Client-Build-Number": OAI_CLIENT_BUILD_NUMBER,
    "OAI-Session-Id": sessionId
  };
}
var TOKEN_TTL_MS = 5 * 60 * 1e3;
var tokenCache = /* @__PURE__ */ new Map();
function cookieKey(cookie) {
  return createHash3("sha256").update(cookie).digest("hex").slice(0, 16);
}
function tokenLookup(cookie) {
  const entry = tokenCache.get(cookieKey(cookie));
  if (!entry) return null;
  if (Date.now() >= entry.expiresAt) {
    tokenCache.delete(cookieKey(cookie));
    return null;
  }
  return entry;
}
var TOKEN_CACHE_MAX = 200;
function tokenStore(cookie, entry) {
  if (tokenCache.size >= TOKEN_CACHE_MAX && !tokenCache.has(cookieKey(cookie))) {
    const firstKey = tokenCache.keys().next().value;
    if (firstKey) tokenCache.delete(firstKey);
  }
  tokenCache.set(cookieKey(cookie), entry);
}
var SESSION_TOKEN_FAMILY_RE = /^__Secure-next-auth\.session-token(?:\.\d+)?$/;
function mergeRefreshedCookie(originalCookie, setCookieHeader) {
  if (!setCookieHeader) return null;
  const matches = Array.from(
    setCookieHeader.matchAll(/(__Secure-next-auth\.session-token(?:\.\d+)?)=([^;,\s]+)/g)
  );
  if (matches.length === 0) return null;
  const refreshed = /* @__PURE__ */ new Map();
  for (const m of matches) refreshed.set(m[1], m[2]);
  let blob = originalCookie.trim();
  if (/^cookie\s*:\s*/i.test(blob)) blob = blob.replace(/^cookie\s*:\s*/i, "");
  if (!/=/.test(blob)) {
    return Array.from(refreshed, ([k, v]) => `${k}=${v}`).join("; ");
  }
  const pairs = blob.split(/;\s*/).filter(Boolean);
  const result = [];
  let mutated = false;
  let droppedStale = false;
  for (const pair of pairs) {
    const eqIdx = pair.indexOf("=");
    if (eqIdx < 0) {
      result.push(pair);
      continue;
    }
    const name = pair.slice(0, eqIdx).trim();
    const value = pair.slice(eqIdx + 1);
    if (SESSION_TOKEN_FAMILY_RE.test(name)) {
      if (!refreshed.has(name) || refreshed.get(name) !== value) mutated = true;
      droppedStale = true;
      continue;
    }
    result.push(`${name}=${value}`);
  }
  for (const [name, value] of refreshed) {
    result.push(`${name}=${value}`);
  }
  if (!droppedStale) mutated = true;
  return mutated ? result.join("; ") : null;
}
function buildSessionCookieHeader(rawInput) {
  let s = rawInput.trim();
  if (/^cookie\s*:\s*/i.test(s)) s = s.replace(/^cookie\s*:\s*/i, "");
  if (/__Secure-next-auth\.session-token(?:\.\d+)?\s*=/.test(s)) {
    return s;
  }
  return `__Secure-next-auth.session-token=${s}`;
}
async function exchangeSession(cookie, signal) {
  const cached = tokenLookup(cookie);
  if (cached) return cached;
  const headers = {
    ...browserHeaders(),
    Accept: "application/json",
    Cookie: buildSessionCookieHeader(cookie)
  };
  const response = await tlsFetchChatGpt(SESSION_URL, {
    method: "GET",
    headers,
    timeoutMs: 3e4,
    signal
  });
  if (response.status === 401 || response.status === 403) {
    throw new SessionAuthError("Invalid session cookie");
  }
  if (response.status >= 400) {
    throw new Error(`Session exchange failed (HTTP ${response.status})`);
  }
  const refreshed = mergeRefreshedCookie(cookie, response.headers.get("set-cookie"));
  let data = {};
  try {
    data = JSON.parse(response.text || "{}");
  } catch {
    console.warn("[chatgpt-web] session response JSON parse failed");
  }
  if (!data.accessToken) {
    throw new SessionAuthError("Session response missing accessToken \u2014 cookie likely expired");
  }
  const expiresAt = data.expires ? new Date(data.expires).getTime() : Date.now() + TOKEN_TTL_MS;
  const entry = {
    accessToken: data.accessToken,
    accountId: data.user?.id ?? null,
    expiresAt: Math.min(expiresAt, Date.now() + TOKEN_TTL_MS),
    refreshedCookie: refreshed ?? void 0
  };
  tokenStore(cookie, entry);
  return entry;
}
var SessionAuthError = class extends Error {
  constructor(message) {
    super(message);
    this.name = "SessionAuthError";
  }
};
var warmupCache = /* @__PURE__ */ new Map();
var WARMUP_TTL_MS = 6e4;
var WARMUP_CACHE_MAX = 200;
async function runSessionWarmup(accessToken, accountId, sessionId, deviceId, cookie, signal, log) {
  const key = cookieKey(cookie) + ":" + accessToken.slice(-8);
  const now = Date.now();
  const last = warmupCache.get(key);
  if (last && now - last < WARMUP_TTL_MS) return;
  if (warmupCache.size >= WARMUP_CACHE_MAX && !warmupCache.has(key)) {
    const first = warmupCache.keys().next().value;
    if (first) warmupCache.delete(first);
  }
  warmupCache.set(key, now);
  const headers = {
    ...browserHeaders(),
    ...oaiHeaders(sessionId, deviceId),
    Accept: "*/*",
    Authorization: `Bearer ${accessToken}`,
    Cookie: buildSessionCookieHeader(cookie),
    Priority: "u=1, i"
  };
  if (accountId) headers["chatgpt-account-id"] = accountId;
  const urls = [
    `${CHATGPT_BASE}/backend-api/me`,
    `${CHATGPT_BASE}/backend-api/conversations?offset=0&limit=28&order=updated`,
    `${CHATGPT_BASE}/backend-api/models?history_and_training_disabled=false`
  ];
  for (const url of urls) {
    try {
      const r = await tlsFetchChatGpt(url, {
        method: "GET",
        headers,
        timeoutMs: 15e3,
        signal
      });
      log?.debug?.("CGPT-WEB", `warmup ${url.split("/backend-api/")[1]} \u2192 ${r.status}`);
    } catch (err) {
      log?.debug?.(
        "CGPT-WEB",
        `warmup ${url} failed: ${err instanceof Error ? err.message : String(err)}`
      );
    }
  }
}
var thinkingEffortCache = /* @__PURE__ */ new Map();
var THINKING_EFFORT_TTL_MS = 5 * 60 * 1e3;
var THINKING_EFFORT_CACHE_MAX = 400;
function configuredProPollTimeoutMs() {
  const raw = Number(process.env.OMNIROUTE_CGPT_WEB_PRO_TIMEOUT_MS);
  if (!Number.isFinite(raw) || raw <= 0) return DEFAULT_PRO_POLL_TIMEOUT_MS;
  return Math.floor(raw);
}
function configuredProPollIntervalMs() {
  const raw = Number(process.env.OMNIROUTE_CGPT_WEB_PRO_POLL_INTERVAL_MS);
  if (!Number.isFinite(raw) || raw <= 0) return DEFAULT_PRO_POLL_INTERVAL_MS;
  return Math.floor(raw);
}
async function setUserThinkingEffort(modelSlug, effort, accessToken, accountId, sessionId, deviceId, cookie, signal, log) {
  const cacheKey = `${cookieKey(cookie)}:${modelSlug}:${effort}`;
  const now = Date.now();
  const last = thinkingEffortCache.get(cacheKey);
  if (last && now - last < THINKING_EFFORT_TTL_MS) {
    log?.debug?.("CGPT-WEB", `thinking_effort cached (${modelSlug}=${effort}) \u2014 skip PATCH`);
    return;
  }
  if (thinkingEffortCache.size >= THINKING_EFFORT_CACHE_MAX && !thinkingEffortCache.has(cacheKey)) {
    const first = thinkingEffortCache.keys().next().value;
    if (first) thinkingEffortCache.delete(first);
  }
  const url = `${USER_LAST_USED_MODEL_CONFIG_URL}?model_slug=${encodeURIComponent(modelSlug)}&thinking_effort=${encodeURIComponent(effort)}`;
  const headers = {
    ...browserHeaders(),
    ...oaiHeaders(sessionId, deviceId),
    Accept: "application/json",
    Authorization: `Bearer ${accessToken}`,
    Cookie: buildSessionCookieHeader(cookie),
    Priority: "u=4"
  };
  if (accountId) headers["chatgpt-account-id"] = accountId;
  try {
    const r = await tlsFetchChatGpt(url, {
      method: "PATCH",
      headers,
      timeoutMs: 15e3,
      signal
    });
    if (r.status >= 400) {
      log?.warn?.(
        "CGPT-WEB",
        `thinking_effort PATCH ${r.status} for ${modelSlug}=${effort} (continuing)`
      );
      return;
    }
    thinkingEffortCache.set(cacheKey, now);
    log?.debug?.("CGPT-WEB", `thinking_effort PATCH OK (${modelSlug}=${effort})`);
  } catch (err) {
    log?.warn?.(
      "CGPT-WEB",
      `thinking_effort PATCH failed: ${err instanceof Error ? err.message : String(err)}`
    );
  }
}
async function prepareChatRequirements(accessToken, accountId, sessionId, deviceId, cookie, dplInfo, signal, log) {
  const config = buildPrekeyConfig(CHATGPT_USER_AGENT, dplInfo.dpl, dplInfo.scriptSrc);
  const prekey = await buildPrepareToken(config, log);
  const headers = {
    ...browserHeaders(),
    ...oaiHeaders(sessionId, deviceId),
    "Content-Type": "application/json",
    Authorization: `Bearer ${accessToken}`,
    Cookie: buildSessionCookieHeader(cookie),
    Priority: "u=1, i"
  };
  if (accountId) headers["chatgpt-account-id"] = accountId;
  const prepResp = await tlsFetchChatGpt(SENTINEL_PREPARE_URL, {
    method: "POST",
    headers,
    body: JSON.stringify({ p: prekey }),
    timeoutMs: 3e4,
    signal
  });
  if (prepResp.status === 401 || prepResp.status === 403) {
    throw new SentinelBlockedError(`Sentinel /prepare blocked (HTTP ${prepResp.status})`);
  }
  if (prepResp.status >= 400) {
    throw new Error(`Sentinel /prepare failed (HTTP ${prepResp.status})`);
  }
  let prepData = {};
  try {
    prepData = JSON.parse(prepResp.text || "{}");
  } catch {
    console.warn("[chatgpt-web] chat requirements prep JSON parse failed");
  }
  if (!prepData.prepare_token) {
    return prepData;
  }
  const crBody = { p: prekey, prepare_token: prepData.prepare_token };
  const crResp = await tlsFetchChatGpt(SENTINEL_CR_URL, {
    method: "POST",
    headers,
    body: JSON.stringify(crBody),
    timeoutMs: 3e4,
    signal
  });
  if (crResp.status === 401 || crResp.status === 403) {
    throw new SentinelBlockedError(`Sentinel /chat-requirements blocked (HTTP ${crResp.status})`);
  }
  if (crResp.status >= 400) {
    return prepData;
  }
  try {
    const crData = JSON.parse(crResp.text || "{}");
    return { ...crData, prepare_token: prepData.prepare_token };
  } catch {
    console.warn("[chatgpt-web] chat requirements response JSON parse failed");
    return prepData;
  }
}
var SentinelBlockedError = class extends Error {
  constructor(message) {
    super(message);
    this.name = "SentinelBlockedError";
  }
};
var dplCache = null;
var DPL_TTL_MS = 60 * 60 * 1e3;
async function fetchDpl(cookie, signal) {
  if (dplCache && Date.now() < dplCache.expiresAt) {
    return { dpl: dplCache.dpl, scriptSrc: dplCache.scriptSrc };
  }
  const headers = {
    ...browserHeaders(),
    Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    Cookie: buildSessionCookieHeader(cookie)
  };
  const response = await tlsFetchChatGpt(`${CHATGPT_BASE}/`, {
    method: "GET",
    headers,
    timeoutMs: 2e4,
    signal
  });
  const html = response.text || "";
  const dplMatch = html.match(/data-build="([^"]+)"/);
  const dpl = dplMatch ? `dpl=${dplMatch[1]}` : `dpl=${OAI_CLIENT_VERSION.replace(/^prod-/, "")}`;
  const scriptMatch = html.match(/<script[^>]+src="(https?:\/\/[^"]*\.js[^"]*)"/);
  const scriptSrc = scriptMatch?.[1] ?? `${CHATGPT_BASE}/_next/static/chunks/webpack-${randomHex(16)}.js`;
  dplCache = { dpl, scriptSrc, expiresAt: Date.now() + DPL_TTL_MS };
  return { dpl, scriptSrc };
}
function randomHex(n) {
  return randomBytes(Math.ceil(n / 2)).toString("hex").slice(0, n);
}
var NAVIGATOR_KEYS = [
  "webdriver\u2212false",
  "geolocation",
  "languages",
  "language",
  "platform",
  "userAgent",
  "vendor",
  "hardwareConcurrency",
  "deviceMemory",
  "permissions",
  "plugins",
  "mediaDevices"
];
var DOCUMENT_KEYS = [
  "_reactListeningkfj3eavmks",
  "_reactListeningo743lnnpvdg",
  "location",
  "scrollingElement",
  "documentElement"
];
var WINDOW_KEYS = [
  "webpackChunk_N_E",
  "__NEXT_DATA__",
  "chrome",
  "history",
  "screen",
  "navigation",
  "scrollX",
  "scrollY"
];
function pick(arr) {
  return arr[Math.floor(Math.random() * arr.length)];
}
function buildPrekeyConfig(userAgent, dpl, scriptSrc) {
  const screenSizes = [3e3, 4e3, 3120, 4160];
  const cores = [8, 16, 24, 32];
  const dateStr = (/* @__PURE__ */ new Date()).toString();
  const perfNow = performance.now();
  const epochOffset = Date.now() - perfNow;
  return [
    pick(screenSizes),
    dateStr,
    4294705152,
    0,
    // mutated by solver
    userAgent,
    scriptSrc,
    dpl,
    "en-US",
    "en-US,en",
    0,
    // mutated by solver
    pick(NAVIGATOR_KEYS),
    pick(DOCUMENT_KEYS),
    pick(WINDOW_KEYS),
    perfNow,
    randomUUID3(),
    "",
    pick(cores),
    epochOffset
  ];
}
var POW_YIELD_EVERY = 1e3;
function yieldToEventLoop() {
  return new Promise((resolve) => setImmediate(resolve));
}
async function solvePow(opts) {
  const cfg = [...opts.config];
  for (let i = 0; i < opts.maxIter; i++) {
    if (i > 0 && i % POW_YIELD_EVERY === 0) await yieldToEventLoop();
    cfg[3] = i;
    const json = JSON.stringify(cfg);
    const b642 = Buffer.from(json).toString("base64");
    const hash = sha3_512Hex(opts.seed + b642);
    if (opts.target && hash.slice(0, opts.target.length) <= opts.target) {
      return `${opts.prefix}${b642}`;
    }
  }
  opts.log?.warn?.(
    "CGPT-WEB",
    `PoW (${opts.label}) exhausted ${opts.maxIter} iterations against target=${opts.target || "<empty>"}; submitting unsolved token (Sentinel may reject)`
  );
  const b64 = Buffer.from(JSON.stringify(cfg)).toString("base64");
  return `${opts.prefix}${b64}`;
}
async function buildPrepareToken(config, log) {
  return solvePow({
    config,
    seed: "",
    target: "0fffff",
    prefix: "gAAAAAC",
    maxIter: 1e5,
    label: "prepare",
    log
  });
}
async function solveProofOfWork(seed, difficulty, config, log) {
  return solvePow({
    config,
    seed,
    target: (difficulty || "").toLowerCase(),
    prefix: "gAAAAAB",
    maxIter: 5e5,
    label: "conversation",
    log
  });
}
var DATA_URI_IMAGE_RE = /!\[([^\]]*)\]\(data:image\/[^)]+\)/g;
var CACHED_IMAGE_URL_RE = /\/v1\/chatgpt-web\/image\/([a-f0-9]{16,64})(?=[)\s"'<>]|$)/gi;
function stripInlinedImages(content) {
  return content.replace(
    DATA_URI_IMAGE_RE,
    (_, alt) => alt ? `[${alt}: generated image]` : "[generated image]"
  );
}
function findCachedImageContext(content) {
  let latest = null;
  for (const match of content.matchAll(CACHED_IMAGE_URL_RE)) {
    const id = match[1];
    const context = getChatGptImageConversationContext(id);
    if (context) latest = context;
  }
  return latest;
}
function parseOpenAIMessages(messages) {
  let systemMsg = "";
  const history = [];
  let latestImageContext = null;
  const imageInputs = [];
  for (const msg of messages) {
    let role = String(msg.role || "user");
    if (role === "developer") role = "system";
    let content = "";
    if (typeof msg.content === "string") {
      content = msg.content;
    } else if (Array.isArray(msg.content)) {
      const parts = msg.content;
      content = parts.filter((c) => c.type === "text").map((c) => String(c.text || "")).join(" ");
      if (role === "user") {
        for (const part of parts) {
          if (part?.type !== "image_url") continue;
          const imageUrl = part.image_url;
          if (typeof imageUrl === "string") imageInputs.push(imageUrl);
          else if (imageUrl && typeof imageUrl === "object" && typeof imageUrl.url === "string") {
            imageInputs.push(String(imageUrl.url));
          }
        }
      }
    }
    content = stripInlinedImages(content);
    const imageContext = findCachedImageContext(content);
    if (imageContext) latestImageContext = imageContext;
    if (!content.trim()) continue;
    if (role === "system") {
      systemMsg += (systemMsg ? "\n" : "") + content;
    } else if (role === "user" || role === "assistant") {
      history.push({ role, content });
    }
  }
  let currentMsg = "";
  if (history.length > 0 && history[history.length - 1].role === "user") {
    currentMsg = history.pop().content;
  }
  return { systemMsg, history, currentMsg, latestImageContext, imageInputs };
}
var IMAGE_GEN_REGEXES = [
  // verb + (anything within 40 chars) + image-noun
  /\b(?:generate|create|make|draw|paint|render|produce|design|sketch|illustrate|show me)\b[\s\S]{0,40}\b(?:image|picture|photo|photograph|drawing|illustration|sketch|painting|portrait|logo|icon|art|artwork|wallpaper|render|graphic)\b/i,
  // image-noun + "of" — "image of a kitten", "picture of mountains"
  /\b(?:image|picture|photo|photograph|illustration|drawing|painting|render)\s+of\b/i,
  // direct verb + a/an article — "draw a kitten", "paint an apple"
  /\b(?:draw|paint|sketch|render|illustrate)\s+(?:me\s+)?(?:a|an|some|the)\s+\w+/i,
  // explicit slash command users sometimes type — "/imagine ..."
  /^\s*\/(?:image|imagine|img|draw|paint)\b/im
];
var OPENWEBUI_TOOL_PROMPT_MARKERS = [
  /<chat_history>/i,
  /^### Task:/im,
  /\bJSON format:\s*\{/i,
  /\bfollow_?ups\b.*\barray of strings\b/i
];
var OPENWEBUI_IMAGE_CONTEXT_MARKERS = [
  /<context>\s*The requested image has been (?:created|edited and created) by the system successfully/i,
  /<context>\s*The requested image has been edited and created and is now being shown to the user/i,
  /<context>\s*Image generation was attempted but failed/i
];
function hasOpenWebUIImageContext(parsed) {
  return OPENWEBUI_IMAGE_CONTEXT_MARKERS.some((re) => re.test(parsed.systemMsg));
}
function looksLikeImageGenRequest(parsed) {
  const text = parsed.currentMsg.trim();
  if (!text) return false;
  if (OPENWEBUI_TOOL_PROMPT_MARKERS.some((re) => re.test(text))) return false;
  if (hasOpenWebUIImageContext(parsed)) return false;
  return IMAGE_GEN_REGEXES.some((re) => re.test(text));
}
var IMAGE_EDIT_REGEXES = [
  /\b(?:edit|adjust|modify|change|update|alter|revise|retouch|fix)\b[\s\S]{0,120}\b(?:it|image|picture|photo|lighting|background|style|color|colour|composition|scene|time of day)\b/i,
  /\b(?:make|turn|set|switch)\s+(?:it|the\s+(?:image|picture|photo|scene))\b[\s\S]{0,120}\b/i,
  /\b(?:add|remove|replace)\b[\s\S]{0,120}\b(?:it|image|picture|photo|background|sky|person|object|text|logo)\b/i,
  /\b(?:brighter|darker|night|daytime|time of day|sunset|sunrise|morning|evening|lighting|relight|background|style)\b/i,
  /^\s*(?:now|then|also)\b[\s\S]{0,120}\b(?:make|turn|change|adjust|add|remove|replace|edit)\b/i
];
function looksLikeImageEditRequest(parsed) {
  if (!parsed.latestImageContext) return false;
  const text = parsed.currentMsg.trim();
  if (!text) return false;
  if (OPENWEBUI_TOOL_PROMPT_MARKERS.some((re) => re.test(text))) return false;
  if (hasOpenWebUIImageContext(parsed)) return false;
  return IMAGE_EDIT_REGEXES.some((re) => re.test(text));
}
function buildConversationBody(parsed, modelSlug, parentMessageId, options) {
  const systemParts = [];
  if (parsed.systemMsg.trim()) {
    systemParts.push(parsed.systemMsg.trim());
  }
  const continuation = options.continuation ?? null;
  if (!continuation && parsed.history.length > 0) {
    const formatted = parsed.history.map((h) => `${h.role === "assistant" ? "Assistant" : "User"}: ${h.content}`).join("\n\n");
    systemParts.push(
      `Prior conversation (for context \u2014 answer only the new user message below):

${formatted}`
    );
  }
  const messages = [];
  if (systemParts.length > 0) {
    messages.push({
      id: randomUUID3(),
      author: { role: "system" },
      content: { content_type: "text", parts: [systemParts.join("\n\n")] }
    });
  }
  const currentUserContent = hasOpenWebUIImageContext(parsed) ? "Briefly acknowledge the image result described in the system context. Do not generate, edit, or request another image." : parsed.currentMsg || "";
  const uploadedImageParts = options.uploadedImageParts ?? [];
  const userContent = uploadedImageParts.length > 0 ? {
    content_type: "multimodal_text",
    parts: [
      currentUserContent,
      ...uploadedImageParts.map((image) => ({
        content_type: "image_asset_pointer",
        asset_pointer: image.assetPointer,
        size_bytes: image.sizeBytes,
        width: image.width,
        height: image.height
      }))
    ]
  } : { content_type: "text", parts: [currentUserContent] };
  messages.push({
    id: randomUUID3(),
    author: { role: "user" },
    content: userContent,
    ...uploadedImageParts.length > 0 ? {
      metadata: {
        system_hints: ["picture_v2"],
        image_feature: "prompt",
        image_prompt_id: "omniroute-image-edit",
        image_send_uuid: randomUUID3(),
        attachments: uploadedImageParts.map((image) => ({
          type: "image",
          asset_pointer: image.assetPointer,
          size_bytes: image.sizeBytes,
          width: image.width,
          height: image.height
        }))
      }
    } : {}
  });
  return {
    action: "next",
    messages,
    model: modelSlug,
    // Text-only API-style requests start fresh because clients replay full
    // history. Generated-image edits are the exception: ChatGPT needs the
    // original conversation node to adjust the actual image, not just a
    // markdown URL echoed back in a synthetic history block.
    conversation_id: continuation?.conversationId ?? null,
    parent_message_id: continuation?.parentMessageId ?? parentMessageId,
    timezone_offset_min: -(/* @__PURE__ */ new Date()).getTimezoneOffset(),
    // Temporary Chat is the default. Disable it only for image generation /
    // image edits, where ChatGPT needs durable conversation state for tools.
    ...uploadedImageParts.length > 0 ? { system_hints: ["picture_v2"] } : {},
    history_and_training_disabled: !options.persistConversation,
    suggestions: [],
    websocket_request_id: randomUUID3(),
    conversation_mode: { kind: "primary_assistant" },
    supports_buffering: true,
    force_parallel_switch: "auto",
    paragen_cot_summary_display_override: "allow",
    ...options.thinkingEffort ? { thinking_effort: options.thinkingEffort } : {}
  };
}
async function* readChatGptSseEvents(body, signal) {
  const reader = body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  let dataLines = [];
  let eventName = null;
  function flush() {
    if (dataLines.length === 0) {
      eventName = null;
      return null;
    }
    const payload = dataLines.join("\n");
    dataLines = [];
    const sseEventName = eventName;
    eventName = null;
    const trimmed = payload.trim();
    if (!trimmed || trimmed === "[DONE]") return "done";
    try {
      const parsed = JSON.parse(trimmed);
      if (sseEventName && !parsed.type) parsed.type = sseEventName;
      return parsed;
    } catch {
      console.warn("[chatgpt-web] stream event JSON parse failed");
      return null;
    }
  }
  try {
    while (true) {
      if (signal?.aborted) return;
      const { value, done } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      while (true) {
        const idx = buffer.indexOf("\n");
        if (idx < 0) break;
        const rawLine = buffer.slice(0, idx);
        buffer = buffer.slice(idx + 1);
        const line = rawLine.endsWith("\r") ? rawLine.slice(0, -1) : rawLine;
        if (line === "") {
          const parsed = flush();
          if (parsed === "done") return;
          if (parsed) yield parsed;
          continue;
        }
        if (line.startsWith("event:")) {
          eventName = line.slice(6).trim();
        } else if (line.startsWith("data:")) {
          dataLines.push(line.slice(5).trimStart());
        }
      }
    }
    buffer += decoder.decode();
    if (buffer.trim().startsWith("data:")) {
      dataLines.push(buffer.trim().slice(5).trimStart());
    }
    const tail = flush();
    if (tail && tail !== "done") yield tail;
  } finally {
    reader.releaseLock();
  }
}
function extractImagePointers(parts) {
  const out = [];
  const estuaryFileIdRe = /[?&]id=(file_[A-Za-z0-9_-]+)/g;
  const seen = /* @__PURE__ */ new WeakSet();
  const visit = (value, depth = 0) => {
    if (typeof value === "string") {
      let match;
      while (match = estuaryFileIdRe.exec(value)) {
        out.push(`sediment://${match[1]}`);
      }
      estuaryFileIdRe.lastIndex = 0;
      return;
    }
    if (!value || typeof value !== "object") return;
    if (depth > 64 || seen.has(value)) return;
    seen.add(value);
    if (Buffer.isBuffer(value) || ArrayBuffer.isView(value)) return;
    const obj = value;
    if (obj.content_type === "image_asset_pointer" && typeof obj.asset_pointer === "string") {
      out.push(obj.asset_pointer);
    }
    for (const child of Object.values(obj)) {
      if (Array.isArray(child)) child.forEach((item) => visit(item, depth + 1));
      else visit(child, depth + 1);
    }
  };
  for (const part of parts) visit(part);
  return Array.from(new Set(out));
}
async function* extractContent(eventStream, signal) {
  let conversationId = null;
  let currentId = null;
  let currentParts = "";
  let currentMetadata;
  let emittedLen = 0;
  let isLive = false;
  const imagePointers = /* @__PURE__ */ new Map();
  let imageGenAsync = false;
  let handoff = false;
  let resumeToken = null;
  for await (const event of readChatGptSseEvents(eventStream, signal)) {
    if (event.error) {
      const msg = typeof event.error === "string" ? event.error : event.error.message || "ChatGPT stream error";
      yield { error: msg, done: true };
      return;
    }
    if (event.conversation_id) conversationId = event.conversation_id;
    if (event.type === "resume_conversation_token") {
      if (typeof event.token === "string" && event.token) resumeToken = event.token;
      continue;
    }
    if (event.type === "stream_handoff") {
      handoff = true;
      yield {
        conversationId: conversationId ?? void 0,
        handoff: true,
        resumeToken: resumeToken ?? void 0
      };
      continue;
    }
    if (event.type === "server_ste_metadata") {
      const meta = event.metadata;
      if (meta && meta.turn_use_case === "image gen") {
        imageGenAsync = true;
      }
    }
    const m = event.message;
    if (!m) continue;
    if (m.metadata && typeof m.metadata.image_gen_task_id === "string") {
      imageGenAsync = true;
    }
    if (m.author?.role !== "assistant") continue;
    const id = m.id ?? null;
    const status = m.status ?? "";
    if (id && id !== currentId) {
      currentId = id;
      currentParts = "";
      currentMetadata = void 0;
      emittedLen = 0;
      isLive = false;
    }
    if (m.metadata && typeof m.metadata === "object") {
      currentMetadata = m.metadata;
    }
    if (status === "in_progress") {
      isLive = true;
    }
    const parts = m.content?.parts ?? [];
    if (parts.length === 0) continue;
    if (status === "finished_successfully" || status === "" || isLive) {
      for (const ptr of extractImagePointers(parts)) {
        const existing = imagePointers.get(ptr);
        imagePointers.set(
          ptr,
          existing?.messageId ? existing : { pointer: ptr, ...id ? { messageId: id } : {} }
        );
      }
    }
    const cumulative = parts.map((p) => typeof p === "string" ? p : "").join("");
    if (cumulative.length > currentParts.length) {
      currentParts = cumulative;
    }
    if (isLive && currentParts.length > emittedLen) {
      const delta = currentParts.slice(emittedLen);
      emittedLen = currentParts.length;
      yield {
        delta,
        answer: currentParts,
        conversationId: conversationId ?? void 0,
        messageId: currentId ?? void 0,
        metadata: currentMetadata
      };
    }
  }
  if (!isLive && currentParts.length > emittedLen) {
    yield {
      delta: currentParts.slice(emittedLen),
      answer: currentParts,
      conversationId: conversationId ?? void 0,
      messageId: currentId ?? void 0,
      metadata: currentMetadata
    };
  }
  yield {
    delta: "",
    answer: currentParts,
    conversationId: conversationId ?? void 0,
    messageId: currentId ?? void 0,
    metadata: currentMetadata,
    imagePointers: imagePointers.size > 0 ? Array.from(imagePointers.values()) : void 0,
    imageGenAsync,
    handoff,
    resumeToken: resumeToken ?? void 0,
    done: true
  };
}
function textFromContentPart(part) {
  if (typeof part === "string") return part;
  if (!part || typeof part !== "object") return "";
  const obj = part;
  for (const key of ["text", "content", "summary"]) {
    const value = obj[key];
    if (typeof value === "string") return value;
  }
  return "";
}
function detailMessageText(message) {
  const content = message.content;
  if (!content) return "";
  if (typeof content.text === "string") return content.text;
  const parts = content.parts ?? [];
  return parts.map(textFromContentPart).join("");
}
function extractFinalAssistantAnswer(detail) {
  const nodes = Object.values(detail.mapping ?? {});
  let best = null;
  for (const node of nodes) {
    const message = node.message;
    if (!message || message.author?.role !== "assistant") continue;
    if (message.metadata?.is_visually_hidden === true) continue;
    const contentType = message.content?.content_type ?? "";
    if (contentType.includes("thought") || contentType.includes("reasoning")) continue;
    const pointers = extractImagePointers([message]).filter((ptr) => !(message.author?.role !== "assistant" && message.author?.role !== "tool" || false));
    const text = detailMessageText(message).trim();
    if (message.author?.role !== "assistant" && message.author?.role !== "tool") continue;
    if (!text && pointers.length === 0) continue;
    const finished = message.status === "finished_successfully" && message.end_turn !== false;
    const sort = message.update_time ?? message.create_time ?? 0;
    if (!best || finished && (!best.finished || sort >= best.sort) || !finished && !best.finished && sort >= best.sort) {
      best = { text, messageId: message.id, metadata: message.metadata, finished, sort };
    }
  }
  if (!best) return null;
  return {
    text: best.text,
    messageId: best.messageId,
    metadata: best.metadata,
    finished: best.finished
  };
}
function delayWithAbort(ms, signal) {
  if (ms <= 0) return Promise.resolve();
  if (signal?.aborted) return Promise.resolve();
  return new Promise((resolve) => {
    const timer = setTimeout(() => {
      signal?.removeEventListener("abort", onAbort);
      resolve();
    }, ms);
    const onAbort = () => {
      clearTimeout(timer);
      signal?.removeEventListener("abort", onAbort);
      resolve();
    };
    signal?.addEventListener("abort", onAbort, { once: true });
  });
}
function decodeUtf8DataUrl(text) {
  const marker = ";base64,";
  if (!text.startsWith("data:") || !text.includes(marker)) return text;
  const base64 = text.slice(text.indexOf(marker) + marker.length);
  return new TextDecoder().decode(Buffer.from(base64, "base64"));
}
async function fetchConversationDetail(conversationId, ctx) {
  const url = `${CHATGPT_BASE}/backend-api/conversation/${encodeURIComponent(conversationId)}`;
  const headers = {
    ...browserHeaders(),
    ...oaiHeaders(ctx.sessionId, ctx.deviceId),
    Accept: "application/json",
    Authorization: `Bearer ${ctx.accessToken}`,
    Cookie: buildSessionCookieHeader(ctx.cookie)
  };
  if (ctx.accountId) headers["chatgpt-account-id"] = ctx.accountId;
  try {
    const response = await tlsFetchChatGpt(url, {
      method: "GET",
      headers,
      timeoutMs: 3e4,
      signal: ctx.signal,
      // The native tls-client text path can surface UTF-8 JSON as mojibake
      // (e.g. 👉 becomes ðŸ‘‰). Ask for raw bytes and decode as UTF-8 here so
      // the final answer appended after Pro stream_handoff preserves Unicode.
      byteResponse: true
    });
    if (response.status >= 400) {
      ctx.log?.warn?.(
        "CGPT-WEB",
        `conversation poll ${response.status}: ${(response.text || "").slice(0, 300)}`
      );
      return { detail: null, terminal: [401, 403, 404].includes(response.status) };
    }
    if (!response.text) return { detail: null, terminal: false };
    return {
      detail: JSON.parse(decodeUtf8DataUrl(response.text)),
      terminal: false
    };
  } catch (err) {
    ctx.log?.warn?.(
      "CGPT-WEB",
      `conversation poll failed: ${err instanceof Error ? err.message : String(err)}`
    );
    return { detail: null, terminal: false };
  }
}
async function fetchImageTasks(ctx) {
  const headers = {
    ...browserHeaders(),
    ...oaiHeaders(ctx.sessionId, ctx.deviceId),
    Accept: "application/json",
    Authorization: `Bearer ${ctx.accessToken}`,
    Cookie: buildSessionCookieHeader(ctx.cookie)
  };
  if (ctx.accountId) headers["chatgpt-account-id"] = ctx.accountId;
  for (const url of [`${CHATGPT_BASE}/backend-api/tasks`, `${CHATGPT_BASE}/backend-api/tasks?cursor=`]) {
    try {
      const response = await tlsFetchChatGpt(url, {
        method: "GET",
        headers,
        timeoutMs: 3e4,
        signal: ctx.signal,
        byteResponse: true
      });
      if (response.status === 200) {
        if (!response.text) return null;
        return JSON.parse(decodeUtf8DataUrl(response.text));
      }
      ctx.log?.warn?.("CGPT-WEB", `tasks poll ${response.status}: ${(response.text || "").slice(0, 200)}`);
    } catch (err) {
      ctx.log?.warn?.("CGPT-WEB", `tasks poll failed: ${err instanceof Error ? err.message : String(err)}`);
    }
  }
  return null;
}
function collectTaskImagePointers(tasksPayload, conversationId, ctx) {
  const found = /* @__PURE__ */ new Map();
  const tasks = Array.isArray(tasksPayload?.tasks) ? tasksPayload.tasks : [tasksPayload];
  const fileIdRe = /\bfile_[A-Za-z0-9_-]{8,}\b/g;
  const addPointer = (ptrOrFileId, messageId) => {
    const ptr = ptrOrFileId.startsWith(FILE_SERVICE_PREFIX) || ptrOrFileId.startsWith(SEDIMENT_PREFIX) ? ptrOrFileId : `${SEDIMENT_PREFIX}${ptrOrFileId}`;
    if (ctx.excludeImagePointers?.has(ptr)) return;
    const existing = found.get(ptr);
    found.set(ptr, existing?.messageId ? existing : { pointer: ptr, ...messageId ? { messageId } : {} });
  };
  for (const task of tasks) {
    if (!task || typeof task !== "object") continue;
    let raw = "";
    try {
      raw = JSON.stringify(task);
    } catch {
    }
    if (conversationId && raw && !raw.includes(conversationId)) continue;
    const obj = task;
    const messageId = String(obj.response_message_id ?? obj.responseMessageId ?? obj.message_id ?? obj.messageId ?? "") || void 0;
    for (const ptr of extractImagePointers([task])) addPointer(ptr, messageId);
    const seen = /* @__PURE__ */ new WeakSet();
    const visit = (value, key, depth = 0) => {
      if (typeof value === "string") {
        const likelyFileField = /(file|image|asset|url|download|content)/i.test(String(key || "")) || value.includes("estuary/content") || value.includes("file_");
        if (likelyFileField) {
          let match;
          while (match = fileIdRe.exec(value)) addPointer(match[0], messageId);
          fileIdRe.lastIndex = 0;
        }
        return;
      }
      if (!value || typeof value !== "object") return;
      if (depth > 64 || seen.has(value)) return;
      seen.add(value);
      if (Buffer.isBuffer(value) || ArrayBuffer.isView(value)) return;
      for (const [childKey, child] of Object.entries(value)) {
        if (Array.isArray(child)) child.forEach((item) => visit(item, childKey, depth + 1));
        else visit(child, childKey, depth + 1);
      }
    };
    visit(task);
  }
  return Array.from(found.values());
}
async function pollForFinalAssistantAnswer(conversationId, ctx) {
  const started = Date.now();
  const timeoutMs = configuredProPollTimeoutMs();
  const intervalMs = configuredProPollIntervalMs();
  let last = null;
  let terminalPollFailure = false;
  while (!ctx.signal?.aborted && Date.now() - started < timeoutMs) {
    const { detail, terminal } = await fetchConversationDetail(conversationId, ctx);
    if (detail) {
      const answer = extractFinalAssistantAnswer(detail);
      if (answer) {
        last = answer;
        if (answer.finished) return answer;
      }
    }
    if (terminal) {
      terminalPollFailure = true;
      break;
    }
    const remaining = timeoutMs - (Date.now() - started);
    if (remaining <= 0) break;
    await delayWithAbort(Math.min(intervalMs, remaining), ctx.signal);
  }
  if (last) {
    ctx.log?.warn?.(
      "CGPT-WEB",
      terminalPollFailure ? `conversation poll stopped before finished_successfully; returning latest assistant text for ${conversationId}` : `conversation poll timed out before finished_successfully; returning latest assistant text for ${conversationId}`
    );
  } else {
    ctx.log?.warn?.(
      "CGPT-WEB",
      terminalPollFailure ? `conversation poll stopped without assistant text for ${conversationId}` : `conversation poll timed out without assistant text for ${conversationId}`
    );
  }
  return last;
}
function sseChunk(data) {
  return `data: ${JSON.stringify(data)}

`;
}
function detectImageResolutionFailure(pointerCount, resolvedCount) {
  return pointerCount > 0 && resolvedCount === 0;
}
function imageMarkdown(urls) {
  if (urls.length === 0) return "";
  return "\n\n" + urls.map((u) => `![image](${u})`).join("\n\n");
}
async function resolveImagePointers(pointers, conversationId, resolver, log, fallbackParentMessageId) {
  if (!pointers || pointers.length === 0 || !resolver) return [];
  const urls = [];
  for (const ref of pointers) {
    try {
      const url = await resolver(
        ref.pointer,
        conversationId,
        ref.messageId ?? fallbackParentMessageId
      );
      if (url) urls.push(url);
    } catch (err) {
      log?.warn?.(
        "CGPT-WEB",
        `Image resolve failed (${ref.pointer}): ${err instanceof Error ? err.message : String(err)}`
      );
    }
  }
  return urls;
}
function buildStreamingResponse(eventStream, model, cid, created, resolver, pollAsyncImage, resumeFinalAnswer, pollFinalAnswer, log, signal) {
  const encoder = new TextEncoder();
  return new ReadableStream(
    {
      async start(controller) {
        try {
          controller.enqueue(
            encoder.encode(
              sseChunk({
                id: cid,
                object: "chat.completion.chunk",
                created,
                model,
                system_fingerprint: null,
                choices: [
                  { index: 0, delta: { role: "assistant" }, finish_reason: null, logprobs: null }
                ]
              })
            )
          );
          let conversationId = null;
          let imagePointers;
          let imageGenAsync = false;
          let handoff = false;
          let resumeToken = null;
          let emittedText = "";
          let polledFinalAnswer = null;
          let parentCandidateMessageId = null;
          const emitRenderedDelta = (content) => {
            if (!content) return;
            emittedText += content;
            controller.enqueue(
              encoder.encode(
                sseChunk({
                  id: cid,
                  object: "chat.completion.chunk",
                  created,
                  model,
                  system_fingerprint: null,
                  choices: [
                    {
                      index: 0,
                      delta: { content },
                      finish_reason: null,
                      logprobs: null
                    }
                  ]
                })
              )
            );
          };
          const emitRenderedAnswer = (rawText, metadata) => {
            const rendered = cleanChatGptText(rawText, metadata);
            if (!rendered || rendered.length <= emittedText.length) return;
            if (!rendered.startsWith(emittedText)) {
              const common = commonPrefixLength(rendered, emittedText);
              if (common < emittedText.length) return;
            }
            emitRenderedDelta(rendered.slice(emittedText.length));
          };
          const appendFinalAnswer = (text, metadata) => {
            const cleaned = cleanChatGptText(text, metadata);
            const finalTrimmed = cleaned.trim();
            if (!finalTrimmed) return;
            const emittedTrimmed = emittedText.trim();
            if (emittedTrimmed === finalTrimmed || emittedTrimmed.endsWith(finalTrimmed)) return;
            const prefix = emittedTrimmed && !emittedText.endsWith("\n") ? "\n\n" : "";
            emitRenderedDelta(`${prefix}${cleaned}`);
          };
          const startHeartbeat = (intervalMs = 5e3) => {
            const heartbeatChunk = sseChunk({
              id: cid,
              object: "chat.completion.chunk",
              created,
              model,
              system_fingerprint: null,
              choices: [{ index: 0, delta: { content: "\u200B" }, finish_reason: null, logprobs: null }]
            });
            const timer = setInterval(() => {
              try {
                controller.enqueue(encoder.encode(heartbeatChunk));
              } catch {
                console.warn("[chatgpt-web] heartbeat enqueue failed - controller closed");
                clearInterval(timer);
              }
            }, intervalMs);
            return () => clearInterval(timer);
          };
          for await (const chunk of extractContent(eventStream, signal)) {
            if (chunk.conversationId) conversationId = chunk.conversationId;
            if (chunk.messageId) parentCandidateMessageId = chunk.messageId;
            if (chunk.handoff) handoff = true;
            if (chunk.resumeToken) resumeToken = chunk.resumeToken;
            if (chunk.error) {
              controller.enqueue(
                encoder.encode(
                  sseChunk({
                    id: cid,
                    object: "chat.completion.chunk",
                    created,
                    model,
                    system_fingerprint: null,
                    choices: [
                      {
                        index: 0,
                        delta: { content: `[Error: ${chunk.error}]` },
                        finish_reason: null,
                        logprobs: null
                      }
                    ]
                  })
                )
              );
              break;
            }
            if (chunk.done) {
              imagePointers = chunk.imagePointers;
              imageGenAsync = chunk.imageGenAsync ?? false;
              handoff = handoff || (chunk.handoff ?? false);
              if (chunk.resumeToken) resumeToken = chunk.resumeToken;
              if (chunk.messageId) parentCandidateMessageId = chunk.messageId;
              break;
            }
            if (chunk.answer) {
              emitRenderedAnswer(chunk.answer, chunk.metadata);
            }
          }
          if (resumeFinalAnswer && conversationId && handoff && resumeToken) {
            const stopHb = startHeartbeat();
            try {
              const resumed = await resumeFinalAnswer(conversationId, resumeToken);
              if (resumed?.text) {
                polledFinalAnswer = resumed;
                if (resumed.messageId) parentCandidateMessageId = resumed.messageId;
              }
            } finally {
              stopHb();
            }
          }
          if (!polledFinalAnswer && pollFinalAnswer && conversationId && handoff) {
            const stopHb = startHeartbeat();
            try {
              const polled = await pollFinalAnswer(conversationId);
              if (polled?.text) {
                polledFinalAnswer = polled;
                if (polled.messageId) parentCandidateMessageId = polled.messageId;
              }
            } finally {
              stopHb();
            }
          }
          if (polledFinalAnswer) {
            appendFinalAnswer(polledFinalAnswer.text, polledFinalAnswer.metadata);
          }
          if (imageGenAsync && conversationId && (!imagePointers || imagePointers.length === 0) && pollAsyncImage) {
            controller.enqueue(
              encoder.encode(
                sseChunk({
                  id: cid,
                  object: "chat.completion.chunk",
                  created,
                  model,
                  system_fingerprint: null,
                  choices: [
                    {
                      index: 0,
                      delta: { content: "_Generating image\u2026_\n\n" },
                      finish_reason: null,
                      logprobs: null
                    }
                  ]
                })
              )
            );
            const stopHb = startHeartbeat();
            try {
              const polled = await pollAsyncImage(conversationId);
              if (polled.length > 0) imagePointers = polled;
            } catch (err) {
              log?.warn?.(
                "CGPT-WEB",
                `Async image poll failed: ${err instanceof Error ? err.message : String(err)}`
              );
            } finally {
              stopHb();
            }
          }
          const stopHb2 = startHeartbeat();
          let urls = [];
          try {
            urls = await resolveImagePointers(
              imagePointers,
              conversationId,
              resolver,
              log,
              parentCandidateMessageId
            );
          } finally {
            stopHb2();
          }
          if (signal?.aborted) return;
          const mdBlock = imageMarkdown(urls);
          const safeEnqueue = (bytes) => {
            try {
              controller.enqueue(bytes);
              return true;
            } catch {
              console.warn("[chatgpt-web] controller enqueue failed");
              return false;
            }
          };
          if (mdBlock) {
            if (!safeEnqueue(
              encoder.encode(
                sseChunk({
                  id: cid,
                  object: "chat.completion.chunk",
                  created,
                  model,
                  system_fingerprint: null,
                  choices: [
                    {
                      index: 0,
                      delta: { content: mdBlock },
                      finish_reason: null,
                      logprobs: null
                    }
                  ]
                })
              )
            ))
              return;
          }
          if (!safeEnqueue(
            encoder.encode(
              sseChunk({
                id: cid,
                object: "chat.completion.chunk",
                created,
                model,
                system_fingerprint: null,
                choices: [{ index: 0, delta: {}, finish_reason: "stop", logprobs: null }]
              })
            )
          ))
            return;
          safeEnqueue(encoder.encode("data: [DONE]\n\n"));
        } catch (err) {
          controller.enqueue(
            encoder.encode(
              sseChunk({
                id: cid,
                object: "chat.completion.chunk",
                created,
                model,
                system_fingerprint: null,
                choices: [
                  {
                    index: 0,
                    delta: {
                      content: `[Stream error: ${err instanceof Error ? err.message : String(err)}]`
                    },
                    finish_reason: "stop",
                    logprobs: null
                  }
                ]
              })
            )
          );
          controller.enqueue(encoder.encode("data: [DONE]\n\n"));
        } finally {
          try {
            controller.close();
          } catch {
          }
        }
      }
    },
    { highWaterMark: 16384 }
  );
}
async function buildNonStreamingResponse(eventStream, model, cid, created, currentMsg, resolver, pollAsyncImage, resumeFinalAnswer, pollFinalAnswer, expectImageOutput, log, signal) {
  let fullAnswer = "";
  let conversationId = null;
  let imagePointers;
  let imageGenAsync = false;
  let handoff = false;
  let resumeToken = null;
  let answerMetadata;
  let parentCandidateMessageId = null;
  for await (const chunk of extractContent(eventStream, signal)) {
    if (chunk.conversationId) conversationId = chunk.conversationId;
    if (chunk.messageId) parentCandidateMessageId = chunk.messageId;
    if (chunk.handoff) handoff = true;
    if (chunk.resumeToken) resumeToken = chunk.resumeToken;
    if (chunk.error) {
      return new Response(
        JSON.stringify({
          error: { message: chunk.error, type: "upstream_error", code: "CHATGPT_ERROR" }
        }),
        { status: 502, headers: { "Content-Type": "application/json" } }
      );
    }
    if (chunk.done) {
      fullAnswer = chunk.answer || fullAnswer;
      answerMetadata = chunk.metadata ?? answerMetadata;
      imagePointers = chunk.imagePointers;
      imageGenAsync = chunk.imageGenAsync ?? false;
      handoff = handoff || (chunk.handoff ?? false);
      if (chunk.resumeToken) resumeToken = chunk.resumeToken;
      if (chunk.messageId) parentCandidateMessageId = chunk.messageId;
      break;
    }
    if (chunk.answer) {
      fullAnswer = chunk.answer;
      answerMetadata = chunk.metadata ?? answerMetadata;
    }
  }
  let resumedAnswer = null;
  if (resumeFinalAnswer && conversationId && handoff && resumeToken) {
    resumedAnswer = await resumeFinalAnswer(conversationId, resumeToken);
    if (resumedAnswer?.text) {
      fullAnswer = resumedAnswer.text;
      answerMetadata = resumedAnswer.metadata ?? answerMetadata;
      if (resumedAnswer.messageId) parentCandidateMessageId = resumedAnswer.messageId;
    }
  }
  if (!resumedAnswer?.text && pollFinalAnswer && conversationId && (handoff || !fullAnswer.trim() || expectImageOutput && (!imagePointers || imagePointers.length === 0))) {
    const polled = await pollFinalAnswer(conversationId);
    if (polled?.text) {
      fullAnswer = polled.text;
      answerMetadata = polled.metadata ?? answerMetadata;
      if (polled.messageId) parentCandidateMessageId = polled.messageId;
    }
  }
  fullAnswer = cleanChatGptText(fullAnswer, answerMetadata);
  if (imageGenAsync && conversationId && (!imagePointers || imagePointers.length === 0) && pollAsyncImage) {
    try {
      const polled = await pollAsyncImage(conversationId);
      if (polled.length > 0) imagePointers = polled;
    } catch (err) {
      log?.warn?.(
        "CGPT-WEB",
        `Async image poll failed: ${err instanceof Error ? err.message : String(err)}`
      );
    }
  }
  const urls = await resolveImagePointers(
    imagePointers,
    conversationId,
    resolver,
    log,
    parentCandidateMessageId
  );
  const imageResolutionFailed = detectImageResolutionFailure(
    imagePointers?.length ?? 0,
    urls.length
  );
  if (imageResolutionFailed && log?.warn) {
    const schemes = (imagePointers ?? []).map((p) => p.pointer.split("://")[0] || p.pointer.slice(0, 24)).join(", ");
    log.warn(
      "CGPT-WEB",
      `Image generated upstream but no asset pointer resolved (schemes: ${schemes}) \u2014 surfacing as unretrievable`
    );
  }
  fullAnswer += imageMarkdown(urls);
  const promptTokens = Math.ceil(currentMsg.length / 4);
  const completionTokens = Math.ceil(fullAnswer.length / 4);
  return new Response(
    JSON.stringify({
      id: cid,
      object: "chat.completion",
      created,
      model,
      system_fingerprint: null,
      ...imageResolutionFailed ? { x_image_resolution_failed: true } : {},
      choices: [
        {
          index: 0,
          message: { role: "assistant", content: fullAnswer },
          finish_reason: "stop",
          logprobs: null
        }
      ],
      usage: {
        prompt_tokens: promptTokens,
        completion_tokens: completionTokens,
        total_tokens: promptTokens + completionTokens
      }
    }),
    { status: 200, headers: { "Content-Type": "application/json" } }
  );
}
function errorResponse(status, message, code) {
  return new Response(
    JSON.stringify({ error: { message, type: "upstream_error", ...code ? { code } : {} } }),
    { status, headers: { "Content-Type": "application/json" } }
  );
}
function normalizePublicBaseUrl(value) {
  const trimmed = value?.trim();
  if (!trimmed) return null;
  return trimmed.replace(/\/+$/, "").replace(/\/v1$/i, "");
}
function firstForwardedValue(value) {
  const first = value?.split(",")[0]?.trim();
  return first || null;
}
function isLocalBaseUrl(baseUrl) {
  try {
    const host = new URL(baseUrl).hostname.toLowerCase();
    return host === "localhost" || host === "127.0.0.1" || host === "::1" || host === "0.0.0.0";
  } catch {
    console.warn("[chatgpt-web] URL parse failed, falling back to regex");
    return /\b(?:localhost|127\.0\.0\.1|0\.0\.0\.0)\b/i.test(baseUrl);
  }
}
function deriveHeaderBaseUrl(clientHeaders) {
  const headers = clientHeaders ?? {};
  const lower = {};
  for (const [k, v] of Object.entries(headers)) lower[k.toLowerCase()] = v;
  const forwardedHost = firstForwardedValue(lower["x-forwarded-host"]);
  const forwardedProto = firstForwardedValue(lower["x-forwarded-proto"]);
  const host = forwardedHost || firstForwardedValue(lower["host"]);
  if (!host) return null;
  const isPlain = host.includes("localhost") || /^\d+\.\d+\.\d+\.\d+(:\d+)?$/.test(host) || host.endsWith(".local") || host.includes(":");
  const proto = forwardedProto || (isPlain ? "http" : "https");
  return `${proto}://${host}`;
}
function derivePublicBaseUrl(clientHeaders, log) {
  const explicitPublicBase = normalizePublicBaseUrl(process.env.OMNIROUTE_PUBLIC_BASE_URL);
  if (explicitPublicBase) {
    log?.debug?.("CGPT-WEB", `derivePublicBaseUrl: using OMNIROUTE_PUBLIC_BASE_URL`);
    return explicitPublicBase;
  }
  const headerBase = deriveHeaderBaseUrl(clientHeaders);
  const configuredBase = normalizePublicBaseUrl(process.env.OMNIROUTE_BASE_URL) || normalizePublicBaseUrl(process.env.NEXT_PUBLIC_BASE_URL);
  log?.debug?.(
    "CGPT-WEB",
    `derivePublicBaseUrl: configured=${configuredBase ?? "-"} header=${headerBase ?? "-"}`
  );
  if (configuredBase && (!headerBase || !isLocalBaseUrl(configuredBase))) return configuredBase;
  if (headerBase) return headerBase;
  if (configuredBase) return configuredBase;
  return `http://localhost:${process.env.PORT || 20128}`;
}
var FILE_SERVICE_PREFIX = "file-service://";
var SEDIMENT_PREFIX = "sediment://";
function chatGptAssetPointerForFileId(fileId) {
  return fileId.startsWith("file_") ? `sediment://${fileId}` : `file-service://${fileId}`;
}
function parseDataImageUrl(url) {
  const match = /^data:([^;,]+);base64,(.+)$/i.exec(url.trim());
  if (!match) return null;
  const mimeType = match[1] || "image/png";
  if (!mimeType.startsWith("image/")) return null;
  return { buffer: Buffer.from(match[2], "base64"), mimeType };
}
function imageExtensionForMimeType(mimeType) {
  if (mimeType.includes("jpeg") || mimeType.includes("jpg")) return "jpg";
  if (mimeType.includes("webp")) return "webp";
  if (mimeType.includes("gif")) return "gif";
  if (mimeType.includes("png")) return "png";
  return "png";
}
function isAwsUploadUrl(url) {
  try {
    return Array.from(new URL(url, CHATGPT_BASE).searchParams.keys()).some((key) => key.toLowerCase() === "x-amz-algorithm");
  } catch {
    return url.toLowerCase().includes("x-amz-algorithm=");
  }
}
function getBasicImageDimensions(buffer, mimeType) {
  try {
    if (mimeType.includes("png") && buffer.length >= 24 && buffer.toString("ascii", 1, 4) === "PNG") {
      return { width: buffer.readUInt32BE(16), height: buffer.readUInt32BE(20) };
    }
    if ((mimeType.includes("jpeg") || mimeType.includes("jpg")) && buffer.length > 4) {
      let offset = 2;
      while (offset + 9 < buffer.length) {
        if (buffer[offset] !== 255) break;
        const marker = buffer[offset + 1];
        const length = buffer.readUInt16BE(offset + 2);
        if (length < 2) break;
        if (marker >= 192 && marker <= 195) {
          return { width: buffer.readUInt16BE(offset + 7), height: buffer.readUInt16BE(offset + 5) };
        }
        offset += 2 + length;
      }
    }
  } catch {
  }
  return { width: 1, height: 1 };
}
function buildMultipartBody(fields, file) {
  const boundary = `----omniroute-chatgpt-${randomUUID3()}`;
  const CRLF = "\r\n";
  const chunks = [];
  for (const [name, value] of Object.entries(fields)) {
    chunks.push(Buffer.from(`--${boundary}${CRLF}Content-Disposition: form-data; name="${name}"${CRLF}${CRLF}${value}${CRLF}`));
  }
  chunks.push(Buffer.from(`--${boundary}${CRLF}Content-Disposition: form-data; name="${file.fieldName}"; filename="${file.filename}"${CRLF}Content-Type: ${file.mimeType}${CRLF}${CRLF}`));
  chunks.push(file.buffer);
  chunks.push(Buffer.from(`${CRLF}--${boundary}--${CRLF}`));
  return { body: Buffer.concat(chunks), contentType: `multipart/form-data; boundary=${boundary}` };
}
async function uploadChatGptImageInput(imageUrl, ctx) {
  const source = parseDataImageUrl(imageUrl);
  if (!source) {
    ctx.log?.warn?.("CGPT-WEB", "Skipping non-data image_url for ChatGPT Web upload");
    return null;
  }
  const extension = imageExtensionForMimeType(source.mimeType);
  const filename = `image.${extension}`;
  const dimensions = getBasicImageDimensions(source.buffer, source.mimeType);
  const headers = {
    ...browserHeaders(),
    ...oaiHeaders(ctx.sessionId, ctx.deviceId),
    Accept: "application/json",
    Authorization: `Bearer ${ctx.accessToken}`,
    Cookie: buildSessionCookieHeader(ctx.cookie),
    "Content-Type": "application/json"
  };
  if (ctx.accountId) headers["chatgpt-account-id"] = ctx.accountId;
  const createResponse = await tlsFetchChatGpt(`${CHATGPT_BASE}/backend-api/files`, {
    method: "POST",
    headers,
    body: JSON.stringify({
      file_name: filename,
      file_size: source.buffer.length,
      use_case: "multimodal",
      timezone_offset_min: (/* @__PURE__ */ new Date()).getTimezoneOffset(),
      reset_rate_limits: false,
      supports_direct_azure_multipart: true,
      mime_type: source.mimeType,
      entry_surface: "image_gen_upload_input"
    }),
    timeoutMs: 6e4,
    signal: ctx.signal
  });
  if (createResponse.status >= 400) {
    ctx.log?.warn?.("CGPT-WEB", `image upload create failed ${createResponse.status}: ${(createResponse.text || "").slice(0, 300)}`);
    return null;
  }
  let created = {};
  try {
    const parsed = JSON.parse(createResponse.text || "{}");
    created = parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : {};
  } catch {
    ctx.log?.warn?.("CGPT-WEB", "image upload create returned non-JSON body");
    return null;
  }
  const fileId = typeof created.file_id === "string" ? created.file_id : "";
  const uploadUrl = typeof created.upload_url === "string" ? created.upload_url : "";
  if (!fileId || !uploadUrl) {
    ctx.log?.warn?.("CGPT-WEB", "image upload create missing file_id/upload_url");
    return null;
  }
  if (!uploadUrl.includes("/api/estuary/upload_content_and_finalize")) {
    const directUrl = new URL(uploadUrl, CHATGPT_BASE).toString();
    const directHeaders = { "Content-Type": source.mimeType };
    if (!isAwsUploadUrl(uploadUrl)) {
      directHeaders["x-ms-blob-type"] = "BlockBlob";
      directHeaders["x-ms-version"] = "2020-04-08";
    }
    const directResponse = await fetch(directUrl, {
      method: "PUT",
      headers: directHeaders,
      body: source.buffer,
      signal: ctx.signal ?? void 0
    });
    if (!directResponse.ok) {
      ctx.log?.warn?.("CGPT-WEB", `image direct upload failed ${directResponse.status}`);
      return null;
    }
    const processHeaders = {
      ...browserHeaders(),
      ...oaiHeaders(ctx.sessionId, ctx.deviceId),
      Accept: "application/json",
      Authorization: `Bearer ${ctx.accessToken}`,
      Cookie: buildSessionCookieHeader(ctx.cookie),
      "Content-Type": "application/json"
    };
    if (ctx.accountId) processHeaders["chatgpt-account-id"] = ctx.accountId;
    const processResponse = await tlsFetchChatGpt(`${CHATGPT_BASE}/backend-api/files/process_upload_stream`, {
      method: "POST",
      headers: processHeaders,
      body: JSON.stringify({
        file_id: fileId,
        use_case: "multimodal",
        index_for_retrieval: false,
        file_name: filename,
        entry_surface: "image_gen_upload_input"
      }),
      timeoutMs: 12e4,
      signal: ctx.signal
    });
    if (processResponse.status >= 400) {
      ctx.log?.warn?.("CGPT-WEB", `image upload process failed ${processResponse.status}`);
      return null;
    }
    return {
      assetPointer: chatGptAssetPointerForFileId(fileId),
      sizeBytes: source.buffer.length,
      width: dimensions.width,
      height: dimensions.height
    };
  }
  const endpoint = new URL(uploadUrl, CHATGPT_BASE).toString();
  const upstreamUploadUrl = new URL(uploadUrl, CHATGPT_BASE).searchParams.get("upload_url") || uploadUrl;
  const multipart = buildMultipartBody(
    {
      upload_url: upstreamUploadUrl,
      file_id: fileId,
      file_name: filename,
      use_case: "multimodal",
      index_for_retrieval: "false",
      entry_surface: "image_gen_upload_input"
    },
    { fieldName: "file", filename, mimeType: source.mimeType, buffer: source.buffer }
  );
  const uploadHeaders = {
    ...browserHeaders(),
    ...oaiHeaders(ctx.sessionId, ctx.deviceId),
    Accept: "application/json",
    Authorization: `Bearer ${ctx.accessToken}`,
    Cookie: buildSessionCookieHeader(ctx.cookie),
    "Content-Type": multipart.contentType
  };
  if (ctx.accountId) uploadHeaders["chatgpt-account-id"] = ctx.accountId;
  const uploadResponse = await tlsFetchChatGpt(endpoint, {
    method: "POST",
    headers: uploadHeaders,
    body: multipart.body,
    timeoutMs: 12e4,
    signal: ctx.signal
  });
  if (uploadResponse.status >= 400) {
    ctx.log?.warn?.("CGPT-WEB", `image upload finalize failed ${uploadResponse.status}: ${(uploadResponse.text || "").slice(0, 300)}`);
    return null;
  }
  return {
    assetPointer: chatGptAssetPointerForFileId(fileId),
    sizeBytes: source.buffer.length,
    width: dimensions.width,
    height: dimensions.height
  };
}
async function uploadChatGptImageInputs(imageInputs, ctx) {
  const uploaded = [];
  for (const imageInput of imageInputs.slice(0, 4)) {
    const part = await uploadChatGptImageInput(imageInput, ctx);
    if (part) uploaded.push(part);
  }
  return uploaded;
}
async function fetchDownloadUrl(endpoint, ctx) {
  const headers = {
    ...browserHeaders(),
    ...oaiHeaders(ctx.sessionId, ctx.deviceId),
    Accept: "application/json",
    Authorization: `Bearer ${ctx.accessToken}`,
    Cookie: buildSessionCookieHeader(ctx.cookie)
  };
  if (ctx.accountId) headers["chatgpt-account-id"] = ctx.accountId;
  const response = await tlsFetchChatGpt(endpoint, {
    method: "GET",
    headers,
    timeoutMs: 3e4,
    signal: ctx.signal
  });
  if (response.status !== 200) {
    ctx.log?.warn?.(
      "CGPT-WEB",
      `Image download URL fetch failed (${response.status}) for ${endpoint}`
    );
    return null;
  }
  let parsed = {};
  try {
    parsed = JSON.parse(response.text || "{}");
  } catch {
    console.warn("[chatgpt-web] image download URL parse failed");
    return null;
  }
  return parsed.download_url ?? null;
}
var IMAGE_DOWNLOAD_MAX_BYTES = 8 * 1024 * 1024;
async function imageUrlToCachedImageUrl(signedUrl, ctx, imageContext) {
  const headers = {
    ...browserHeaders(),
    Accept: "image/*,*/*;q=0.8",
    Authorization: `Bearer ${ctx.accessToken}`,
    Cookie: buildSessionCookieHeader(ctx.cookie)
  };
  if (ctx.accountId) headers["chatgpt-account-id"] = ctx.accountId;
  let response;
  try {
    response = await tlsFetchChatGpt(signedUrl, {
      method: "GET",
      headers,
      timeoutMs: 6e4,
      signal: ctx.signal,
      // Required for binary payloads — the underlying tls-client returns
      // bytes as a `data:<mime>;base64,...` string when this is true.
      // Without it, raw image bytes get mangled by UTF-8 decoding.
      byteResponse: true
    });
  } catch (err) {
    ctx.log?.warn?.(
      "CGPT-WEB",
      `Image fetch failed: ${err instanceof Error ? err.message : String(err)}`
    );
    return null;
  }
  if (response.status !== 200) {
    ctx.log?.warn?.(
      "CGPT-WEB",
      `Image fetch returned HTTP ${response.status} (${(response.text || "").slice(0, 120)})`
    );
    return null;
  }
  if (response.text == null || response.text.length === 0) return null;
  let bytes;
  let mime;
  if (/^data:[^;]{1,256};base64,/.test(response.text)) {
    const commaIdx = response.text.indexOf(",");
    const header = response.text.slice(5, commaIdx);
    mime = header.split(";")[0] || "image/png";
    bytes = Buffer.from(response.text.slice(commaIdx + 1), "base64");
  } else {
    bytes = Buffer.from(response.text, "binary");
    mime = response.headers.get("content-type")?.split(";")[0]?.trim() || "image/png";
  }
  if (bytes.length === 0 || bytes.length > IMAGE_DOWNLOAD_MAX_BYTES) {
    if (bytes.length > IMAGE_DOWNLOAD_MAX_BYTES) {
      ctx.log?.warn?.(
        "CGPT-WEB",
        `Image too large to cache (${bytes.length} bytes > ${IMAGE_DOWNLOAD_MAX_BYTES}); skipping`
      );
    }
    return null;
  }
  const id = storeChatGptImage(bytes, mime, void 0, imageContext);
  return `${ctx.publicBaseUrl}/v1/chatgpt-web/image/${id}`;
}
async function registerWebSocket(ctx) {
  const candidates = [
    { url: `${CHATGPT_BASE}/backend-api/celsius/ws/user`, method: "GET" },
    { url: `${CHATGPT_BASE}/backend-api/register-websocket`, method: "POST" }
  ];
  const headers = {
    ...browserHeaders(),
    ...oaiHeaders(ctx.sessionId, ctx.deviceId),
    Accept: "application/json",
    Authorization: `Bearer ${ctx.accessToken}`,
    Cookie: buildSessionCookieHeader(ctx.cookie)
  };
  if (ctx.accountId) headers["chatgpt-account-id"] = ctx.accountId;
  for (const { url, method } of candidates) {
    let r;
    try {
      r = await tlsFetchChatGpt(url, {
        method,
        headers,
        body: method === "POST" ? "" : void 0,
        timeoutMs: 3e4,
        signal: ctx.signal
      });
    } catch (err) {
      ctx.log?.warn?.(
        "CGPT-WEB",
        `register-websocket fetch failed for ${url}: ${err instanceof Error ? err.message : String(err)}`
      );
      continue;
    }
    if (r.status === 200) {
      try {
        const data = JSON.parse(r.text || "{}");
        const ws = data.websocket_url ?? data.wss_url;
        if (ws) {
          ctx.log?.debug?.("CGPT-WEB", `Got WebSocket URL via ${url}`);
          return ws;
        }
      } catch {
        console.warn("[chatgpt-web] WebSocket URL parse failed, falling through");
      }
    }
    ctx.log?.warn?.(
      "CGPT-WEB",
      `register-websocket via ${url} \u2192 ${r.status}: ${(r.text || "").slice(0, 200)}`
    );
  }
  return null;
}
async function waitForImageViaWebSocket(wssUrl, conversationId, timeoutMs, ctx) {
  return new Promise((resolve) => {
    const found = /* @__PURE__ */ new Map();
    let resolved = false;
    let errored = false;
    let gotAnyMessage = false;
    const finish = () => {
      if (resolved) return;
      resolved = true;
      try {
        ws.close();
      } catch {
        console.warn("[chatgpt-web] ws.close failed");
      }
      resolve({
        pointers: Array.from(found.values()),
        errored,
        gotAnyMessage
      });
    };
    const ws = new WebSocket(wssUrl);
    const timer = setTimeout(() => {
      ctx.log?.warn?.("CGPT-WEB", `WebSocket image wait timed out after ${timeoutMs}ms`);
      finish();
    }, timeoutMs);
    const onAbort = () => {
      ctx.log?.debug?.("CGPT-WEB", "WebSocket aborted by client");
      finish();
    };
    ctx.signal?.addEventListener?.("abort", onAbort);
    ws.onopen = () => {
      gotAnyMessage = true;
      ctx.log?.debug?.("CGPT-WEB", "WebSocket open \u2014 waiting for image events");
    };
    ws.onerror = (e) => {
      errored = true;
      ctx.log?.warn?.("CGPT-WEB", `WebSocket error: ${e.message ?? "unknown"}`);
    };
    ws.onclose = () => {
      clearTimeout(timer);
      ctx.signal?.removeEventListener?.("abort", onAbort);
      finish();
    };
    ws.onmessage = (event) => {
      gotAnyMessage = true;
      let payload;
      const raw = typeof event.data === "string" ? event.data : event.data.toString();
      try {
        payload = JSON.parse(raw);
      } catch {
        console.warn("[chatgpt-web] WebSocket event JSON parse failed");
        return;
      }
      const obj = payload;
      const candidates = [];
      const innerPayload = obj.payload;
      const updateContent = innerPayload?.update_content;
      if (updateContent?.message) {
        candidates.push({
          message: updateContent.message,
          conversation_id: innerPayload?.conversation_id
        });
      }
      if (innerPayload?.message) {
        candidates.push({
          message: innerPayload.message,
          conversation_id: innerPayload.conversation_id
        });
      }
      if (obj.data?.message) {
        candidates.push(obj.data);
      }
      for (const data of candidates) {
        if (data?.conversation_id && data.conversation_id !== conversationId) continue;
        const m = data?.message;
        const role = m?.author?.role;
        if (role !== "assistant" && role !== "tool") continue;
        if (Array.isArray(m?.content?.parts)) {
          for (const ptr of extractImagePointers([m])) {
            if (ctx.excludeImagePointers?.has(ptr)) continue;
            const existing = found.get(ptr);
            found.set(
              ptr,
              existing?.messageId ? existing : { pointer: ptr, ...m?.id ? { messageId: m.id } : {} }
            );
          }
        }
        if (m?.metadata && typeof m.metadata === "object") {
          const md = m.metadata;
          const ptr = md.asset_pointer ?? md.image_asset_pointer;
          if (typeof ptr === "string") {
            if (ctx.excludeImagePointers?.has(ptr)) continue;
            const existing = found.get(ptr);
            found.set(
              ptr,
              existing?.messageId ? existing : { pointer: ptr, ...m?.id ? { messageId: m.id } : {} }
            );
          }
        }
      }
      if (found.size > 0) finish();
    };
  });
}
var DEFAULT_ASYNC_IMAGE_TIMEOUT_MS = 15e4;
function configuredAsyncImageTimeoutMs() {
  const raw = Number(process.env.OMNIROUTE_CGPT_WEB_IMAGE_TIMEOUT_MS);
  if (!Number.isFinite(raw) || raw <= 0) return DEFAULT_ASYNC_IMAGE_TIMEOUT_MS;
  return Math.floor(raw);
}
function configuredAsyncImageWsTimeoutMs() {
  const raw = Number(process.env.OMNIROUTE_CGPT_WEB_IMAGE_WS_TIMEOUT_MS);
  if (!Number.isFinite(raw) || raw <= 0) return 3e4;
  return Math.floor(raw);
}
async function pollForAsyncImage(conversationId, ctx, opts = {}) {
  const totalTimeoutMs = opts.timeoutMs ?? configuredAsyncImageTimeoutMs();
  const deadline = Date.now() + totalTimeoutMs;
  for (let attempt = 0; attempt < 2; attempt++) {
    const remaining = deadline - Date.now();
    if (remaining <= 0) break;
    const wssUrl = await registerWebSocket(ctx);
    if (!wssUrl) {
      ctx.log?.warn?.(
        "CGPT-WEB",
        attempt === 0 ? "Could not register WebSocket \u2014 async image gen not retrievable" : `WebSocket re-registration failed on retry attempt ${attempt + 1}`
      );
      if (attempt === 0) continue;
      break;
    }
    ctx.log?.debug?.(
      "CGPT-WEB",
      `Registered WebSocket for async image (attempt ${attempt + 1}, ${remaining}ms remaining)`
    );
    const outcome = await waitForImageViaWebSocket(
      wssUrl,
      conversationId,
      Math.min(remaining, configuredAsyncImageWsTimeoutMs()),
      ctx
    );
    if (outcome.pointers.length > 0) return outcome.pointers;
    if (ctx.signal?.aborted) return [];
    if (!outcome.errored || outcome.gotAnyMessage) break;
    ctx.log?.warn?.(
      "CGPT-WEB",
      `WebSocket attempt ${attempt + 1} ended in transport error before any frame; retrying`
    );
  }
  while (!ctx.signal?.aborted && Date.now() < deadline) {
    const found = /* @__PURE__ */ new Map();
    const { detail } = await fetchConversationDetail(conversationId, ctx);
    if (detail) {
      for (const node of Object.values(detail.mapping ?? {})) {
        const message = node.message;
        if (!message) continue;
        const role = message.author?.role;
        if (role !== "assistant" && role !== "tool") continue;
        for (const ptr of extractImagePointers([message])) {
          if (ctx.excludeImagePointers?.has(ptr)) continue;
          const existing = found.get(ptr);
          found.set(ptr, existing?.messageId ? existing : { pointer: ptr, ...message.id ? { messageId: message.id } : {} });
        }
        if (message.metadata && typeof message.metadata === "object") {
          const md = message.metadata;
          const ptr = md.asset_pointer ?? md.image_asset_pointer;
          if (typeof ptr === "string" && !ctx.excludeImagePointers?.has(ptr)) {
            const existing = found.get(ptr);
            found.set(ptr, existing?.messageId ? existing : { pointer: ptr, ...message.id ? { messageId: message.id } : {} });
          }
        }
      }
      if (found.size > 0) return Array.from(found.values());
    }
    const tasks = await fetchImageTasks(ctx);
    if (tasks) {
      const pointers = collectTaskImagePointers(tasks, conversationId, ctx);
      if (pointers.length > 0) return pointers;
    }
    const remaining = deadline - Date.now();
    if (remaining <= 0) break;
    await delayWithAbort(Math.min(4e3, remaining), ctx.signal);
  }
  return [];
}
function makeImageResolver(ctx) {
  const cache2 = /* @__PURE__ */ new Map();
  return async (assetPointer, conversationId, parentMessageId) => {
    if (cache2.has(assetPointer)) return cache2.get(assetPointer) ?? null;
    let fileId = null;
    if (assetPointer.startsWith(FILE_SERVICE_PREFIX)) {
      fileId = assetPointer.slice(FILE_SERVICE_PREFIX.length);
    } else if (assetPointer.startsWith(SEDIMENT_PREFIX)) {
      fileId = assetPointer.slice(SEDIMENT_PREFIX.length);
    } else {
      ctx.log?.warn?.("CGPT-WEB", `Unknown asset_pointer scheme: ${assetPointer}`);
    }
    let signedUrl = null;
    if (fileId) {
      signedUrl = await fetchDownloadUrl(
        `${CHATGPT_BASE}/backend-api/files/${encodeURIComponent(fileId)}/download`,
        ctx
      );
      if (!signedUrl && conversationId) {
        signedUrl = await fetchDownloadUrl(
          `${CHATGPT_BASE}/backend-api/conversation/${encodeURIComponent(conversationId)}/attachment/${encodeURIComponent(fileId)}/download`,
          ctx
        );
      }
    }
    let finalUrl = null;
    if (signedUrl) {
      finalUrl = await imageUrlToCachedImageUrl(
        signedUrl,
        ctx,
        conversationId && parentMessageId ? { conversationId, parentMessageId } : void 0
      );
    }
    cache2.set(assetPointer, finalUrl);
    if (finalUrl) {
      const preview = finalUrl.startsWith("data:") ? `data:... (${finalUrl.length} chars)` : finalUrl.slice(0, 80) + "...";
      ctx.log?.debug?.("CGPT-WEB", `Resolved ${assetPointer} \u2192 ${preview}`);
    }
    return finalUrl;
  };
}
var ChatGptWebExecutor = class extends BaseExecutor {
  constructor() {
    super("chatgpt-web", { id: "chatgpt-web", baseUrl: CONV_URL });
  }
  async execute({
    model,
    body,
    stream,
    credentials,
    signal,
    log,
    onCredentialsRefreshed,
    clientHeaders
  }) {
    const messages = body?.messages;
    if (!messages || !Array.isArray(messages) || messages.length === 0) {
      return {
        response: errorResponse(400, "Missing or empty messages array"),
        url: CONV_URL,
        headers: {},
        transformedBody: body
      };
    }
    const { hasTools, requestedTools, effectiveMessages } = prepareToolMessages(
      body || {},
      messages
    );
    if (!credentials.apiKey) {
      return {
        response: errorResponse(
          401,
          "ChatGPT auth failed \u2014 paste your __Secure-next-auth.session-token cookie value."
        ),
        url: CONV_URL,
        headers: {},
        transformedBody: body
      };
    }
    const cookie = credentials.apiKey;
    let tokenEntry;
    try {
      tokenEntry = await exchangeSession(cookie, signal);
    } catch (err) {
      if (err instanceof SessionAuthError) {
        log?.warn?.("CGPT-WEB", err.message);
        return {
          response: errorResponse(
            401,
            "ChatGPT auth failed \u2014 re-paste your __Secure-next-auth.session-token cookie from chatgpt.com.",
            "HTTP_401"
          ),
          url: SESSION_URL,
          headers: {},
          transformedBody: body
        };
      }
      log?.error?.(
        "CGPT-WEB",
        `Session exchange failed: ${err instanceof Error ? err.message : String(err)}`
      );
      return {
        response: errorResponse(
          502,
          `ChatGPT session exchange failed: ${err instanceof Error ? err.message : String(err)}`
        ),
        url: SESSION_URL,
        headers: {},
        transformedBody: body
      };
    }
    if (tokenEntry.refreshedCookie && tokenEntry.refreshedCookie !== cookie) {
      const updated = { ...credentials, apiKey: tokenEntry.refreshedCookie };
      try {
        await onCredentialsRefreshed?.(updated);
      } catch (err) {
        log?.warn?.(
          "CGPT-WEB",
          `Failed to persist refreshed cookie: ${err instanceof Error ? err.message : String(err)}`
        );
      }
    }
    let dplInfo;
    try {
      dplInfo = await fetchDpl(cookie, signal);
    } catch (err) {
      log?.warn?.(
        "CGPT-WEB",
        `DPL warmup failed (continuing with fallback): ${err instanceof Error ? err.message : String(err)}`
      );
      dplInfo = {
        dpl: `dpl=${OAI_CLIENT_VERSION.replace(/^prod-/, "")}`,
        scriptSrc: `${CHATGPT_BASE}/_next/static/chunks/webpack-${randomHex(16)}.js`
      };
    }
    const sessionId = randomUUID3();
    const turnTraceId = randomUUID3();
    const deviceId = deviceIdFor(cookie);
    await runSessionWarmup(
      tokenEntry.accessToken,
      tokenEntry.accountId,
      sessionId,
      deviceId,
      cookie,
      signal,
      log
    );
    const resolvedModel = resolveChatGptModel(model, body, credentials.providerSpecificData);
    const modelSlug = resolvedModel.slug;
    const requestedEffort = resolvedModel.effort;
    if (requestedEffort && isThinkingCapableModel(model, modelSlug)) {
      await setUserThinkingEffort(
        modelSlug,
        requestedEffort,
        tokenEntry.accessToken,
        tokenEntry.accountId,
        sessionId,
        deviceId,
        cookie,
        signal,
        log
      );
    }
    let reqs;
    try {
      reqs = await prepareChatRequirements(
        tokenEntry.accessToken,
        tokenEntry.accountId,
        sessionId,
        deviceId,
        cookie,
        dplInfo,
        signal,
        log
      );
    } catch (err) {
      if (err instanceof SentinelBlockedError) {
        log?.warn?.("CGPT-WEB", err.message);
        return {
          response: errorResponse(
            403,
            "ChatGPT blocked the request (Sentinel/Turnstile required). Try again later or open chatgpt.com in a browser to refresh state.",
            "SENTINEL_BLOCKED"
          ),
          url: SENTINEL_PREPARE_URL,
          headers: {},
          transformedBody: body
        };
      }
      log?.error?.(
        "CGPT-WEB",
        `Sentinel failed: ${err instanceof Error ? err.message : String(err)}`
      );
      return {
        response: errorResponse(
          502,
          `ChatGPT sentinel failed: ${err instanceof Error ? err.message : String(err)}`
        ),
        url: SENTINEL_PREPARE_URL,
        headers: {},
        transformedBody: body
      };
    }
    log?.debug?.(
      "CGPT-WEB",
      `sentinel: token=${reqs.token ? "y" : "n"} pow=${reqs.proofofwork?.required ? "y" : "n"} turnstile=${reqs.turnstile?.required ? "y" : "n"}`
    );
    const turnstileToken = typeof credentials.providerSpecificData?.turnstileToken === "string" ? credentials.providerSpecificData.turnstileToken : null;
    let proofToken = null;
    if (reqs.proofofwork?.required && reqs.proofofwork.seed && reqs.proofofwork.difficulty) {
      const powConfig = buildPrekeyConfig(CHATGPT_USER_AGENT, dplInfo.dpl, dplInfo.scriptSrc);
      proofToken = await solveProofOfWork(
        reqs.proofofwork.seed,
        reqs.proofofwork.difficulty,
        powConfig,
        log
      );
    }
    const parsed = parseOpenAIMessages(effectiveMessages);
    if (!parsed.currentMsg.trim() && parsed.history.length === 0) {
      return {
        response: errorResponse(400, "Empty user message"),
        url: CONV_URL,
        headers: {},
        transformedBody: body
      };
    }
    const imageEdit = looksLikeImageEditRequest(parsed);
    const continuation = imageEdit ? parsed.latestImageContext : null;
    const forImageGen = looksLikeImageGenRequest(parsed) || imageEdit;
    const persistConversation = forImageGen || !!continuation;
    if (forImageGen) {
      log?.debug?.(
        "CGPT-WEB",
        continuation ? "Image edit intent detected \u2014 continuing saved image conversation" : "Image-gen intent detected \u2014 disabling Temporary Chat for this turn"
      );
    } else if (resolvedModel.isPro) {
      log?.debug?.("CGPT-WEB", "GPT-5.5 Pro text request \u2014 keeping Temporary Chat enabled");
    }
    const uploadCtx = {
      accessToken: tokenEntry.accessToken,
      accountId: tokenEntry.accountId,
      sessionId,
      deviceId,
      cookie,
      signal,
      log,
      publicBaseUrl: derivePublicBaseUrl(clientHeaders, log)
    };
    const uploadedImageParts = parsed.imageInputs.length > 0 ? await uploadChatGptImageInputs(parsed.imageInputs, uploadCtx) : [];
    if (parsed.imageInputs.length > 0 && uploadedImageParts.length === 0) {
      return {
        response: errorResponse(502, "ChatGPT Web image upload failed"),
        url: CONV_URL,
        headers: {},
        transformedBody: body
      };
    }
    const parentMessageId = continuation?.parentMessageId ?? randomUUID3();
    const cgptBody = buildConversationBody(parsed, modelSlug, parentMessageId, {
      persistConversation,
      thinkingEffort: requestedEffort,
      continuation,
      uploadedImageParts
    });
    const headers = {
      ...browserHeaders(),
      ...oaiHeaders(sessionId, deviceId),
      "Content-Type": "application/json",
      Accept: "text/event-stream",
      Authorization: `Bearer ${tokenEntry.accessToken}`,
      Cookie: buildSessionCookieHeader(cookie),
      "x-oai-turn-trace-id": turnTraceId
    };
    if (tokenEntry.accountId) headers["chatgpt-account-id"] = tokenEntry.accountId;
    if (reqs.token) headers["openai-sentinel-chat-requirements-token"] = reqs.token;
    if (reqs.prepare_token)
      headers["openai-sentinel-chat-requirements-prepare-token"] = reqs.prepare_token;
    if (proofToken) headers["openai-sentinel-proof-token"] = proofToken;
    if (turnstileToken) headers["openai-sentinel-turnstile-token"] = turnstileToken;
    log?.info?.("CGPT-WEB", `Conversation request \u2192 ${modelSlug} (pow=${!!proofToken})`);
    let response;
    try {
      response = await tlsFetchChatGpt(CONV_URL, {
        method: "POST",
        headers,
        body: JSON.stringify(cgptBody),
        timeoutMs: forImageGen ? 36e4 : 12e4,
        // image generation/edit can take a while
        signal,
        // For real-time streaming, ask the TLS client to write the body to
        // a temp file and surface it as a ReadableStream as it arrives —
        // otherwise long generations buffer entirely before the client sees
        // anything (and the downstream HTTP request can time out).
        stream
      });
    } catch (err) {
      log?.error?.("CGPT-WEB", `Fetch failed: ${err instanceof Error ? err.message : String(err)}`);
      const code = err instanceof TlsClientUnavailableError ? "TLS_UNAVAILABLE" : void 0;
      return {
        response: errorResponse(
          502,
          `ChatGPT connection failed: ${err instanceof Error ? err.message : String(err)}`,
          code
        ),
        url: CONV_URL,
        headers,
        transformedBody: cgptBody
      };
    }
    if (response.status >= 400) {
      const status = response.status;
      log?.warn?.("CGPT-WEB", `conv ${status}: ${(response.text || "").slice(0, 400)}`);
      const errMsg = describeChatGptWebHttpError(status);
      if (status === 401 || status === 403) {
        tokenCache.delete(cookieKey(cookie));
      }
      log?.warn?.("CGPT-WEB", errMsg);
      return {
        response: errorResponse(status, errMsg, `HTTP_${status}`),
        url: CONV_URL,
        headers,
        transformedBody: cgptBody
      };
    }
    let bodyStream;
    if (response.body) {
      bodyStream = response.body;
    } else if (response.text) {
      bodyStream = stringToStream2(response.text);
    } else {
      return {
        response: errorResponse(502, "ChatGPT returned empty response body"),
        url: CONV_URL,
        headers,
        transformedBody: cgptBody
      };
    }
    const cid = `chatcmpl-cgpt-${crypto.randomUUID().slice(0, 12)}`;
    const created = Math.floor(Date.now() / 1e3);
    const resolverCtx = {
      accessToken: tokenEntry.accessToken,
      accountId: tokenEntry.accountId,
      sessionId,
      deviceId,
      cookie,
      signal,
      log,
      publicBaseUrl: derivePublicBaseUrl(clientHeaders, log),
      excludeImagePointers: new Set(uploadedImageParts.map((image) => image.assetPointer))
    };
    const imageResolver = makeImageResolver(resolverCtx);
    const pollAsyncImage = (conversationId) => pollForAsyncImage(conversationId, resolverCtx);
    const resumeFinalAnswer = (conversationId, resumeToken) => resumeChatGptHandoff({
      conversationId,
      resumeToken,
      headers,
      timeoutMs: configuredProPollTimeoutMs(),
      signal,
      log,
      readContent: extractContent
    });
    const pollFinalAnswer = resolvedModel.isPro ? (conversationId) => pollForFinalAssistantAnswer(conversationId, resolverCtx) : null;
    const toolMode = hasTools && !forImageGen;
    let finalResponse;
    if (stream && !toolMode) {
      const sseStream = buildStreamingResponse(
        bodyStream,
        model,
        cid,
        created,
        imageResolver,
        pollAsyncImage,
        resumeFinalAnswer,
        pollFinalAnswer,
        log,
        signal
      );
      finalResponse = new Response(sseStream, {
        status: 200,
        headers: {
          "Content-Type": "text/event-stream",
          "Cache-Control": "no-cache",
          "X-Accel-Buffering": "no"
        }
      });
    } else {
      finalResponse = await buildNonStreamingResponse(
        bodyStream,
        model,
        cid,
        created,
        parsed.currentMsg,
        imageResolver,
        pollAsyncImage,
        resumeFinalAnswer,
        pollFinalAnswer,
        forImageGen || uploadedImageParts.length > 0,
        log,
        signal
      );
      if (toolMode) {
        finalResponse = await buildToolModeResponse(finalResponse, requestedTools, stream, {
          cid,
          created,
          model
        });
      }
    }
    return { response: finalResponse, url: CONV_URL, headers, transformedBody: cgptBody };
  }
};
function commonPrefixLength(a, b) {
  const n = Math.min(a.length, b.length);
  let i = 0;
  while (i < n && a.charCodeAt(i) === b.charCodeAt(i)) i++;
  return i;
}
function stringToStream2(text) {
  const encoder = new TextEncoder();
  return new ReadableStream({
    start(controller) {
      controller.enqueue(encoder.encode(text));
      controller.close();
    }
  });
}

// build/plugin-entry.ts
var createExecutor = () => new ChatGptWebExecutor();
var IMAGE_MARKDOWN_RE = /!\[[^\]]*\]\(([^)\s]+)\)/g;
var IMAGE_ID_RE = /\/v1\/chatgpt-web\/image\/([a-f0-9]{16,64})(?=[?\s"'<>)]|$)/i;
var RATE_LIMIT_RE = /you.ve hit the.*plan limit for image|you.ve hit your image generation limit|image generation.*limit.*reset|limit resets in|create more images when the limit|reached the.*limit.*image/i;
function fail(status, error) {
  return { success: false, status, error };
}
function promptOf(ctx) {
  return typeof ctx.body.prompt === "string" ? ctx.body.prompt.trim() : "";
}
function credentialsOf(ctx) {
  return ctx.credentials && typeof ctx.credentials.apiKey === "string" && ctx.credentials.apiKey ? ctx.credentials : null;
}
function numberConfig(ctx, key) {
  const value = ctx.config[key];
  return typeof value === "number" && Number.isFinite(value) && value > 0 ? String(Math.floor(value)) : null;
}
function configureRuntime(ctx) {
  setPluginProxyUrl(
    typeof ctx.proxyUrl === "string" && ctx.proxyUrl.trim() ? ctx.proxyUrl.trim() : typeof ctx.config.proxyUrl === "string" && ctx.config.proxyUrl.trim() ? ctx.config.proxyUrl.trim() : null
  );
  for (const [configKey, envKey] of [
    ["imageTimeoutMs", "OMNIROUTE_CGPT_WEB_IMAGE_TIMEOUT_MS"],
    ["imageWsTimeoutMs", "OMNIROUTE_CGPT_WEB_IMAGE_WS_TIMEOUT_MS"],
    ["proTimeoutMs", "OMNIROUTE_CGPT_WEB_PRO_TIMEOUT_MS"]
  ]) {
    const value = numberConfig(ctx, configKey);
    if (value) process.env[envKey] = value;
    else delete process.env[envKey];
  }
}
function generationPrompt(ctx) {
  const details = [`Create an image for this prompt: ${promptOf(ctx)}`];
  for (const [label, key] of [
    ["Requested size", "size"],
    ["Requested quality", "quality"],
    ["Requested style", "style"]
  ]) {
    const value = ctx.body[key];
    if (typeof value === "string" && value.trim()) details.push(`${label}: ${value.trim()}.`);
  }
  return details.join("\n");
}
function editMessages(ctx) {
  return [
    {
      role: "user",
      content: [
        {
          type: "text",
          text: `Edit the attached image(s) and generate the new image: ${promptOf(ctx)}`
        },
        ...ctx.images.slice(0, 4).map((image) => ({
          type: "image_url",
          image_url: { url: `data:${image.mime};base64,${image.base64}` }
        }))
      ]
    }
  ];
}
function upstreamErrorBody(text) {
  try {
    const parsed = JSON.parse(text);
    return String(parsed?.error?.message || parsed?.error || text);
  } catch {
    return text;
  }
}
async function executeForImages(ctx, messages) {
  const credentials = credentialsOf(ctx);
  if (!credentials) return fail(401, "ChatGPT Web credentials missing session cookie");
  configureRuntime(ctx);
  let execution;
  try {
    execution = await createExecutor().execute({
      model: ctx.model,
      body: { messages },
      stream: false,
      credentials,
      clientHeaders: ctx.clientHeaders
    });
  } catch (error) {
    return fail(
      502,
      `ChatGPT Web provider failed: ${error instanceof Error ? error.message : String(error)}`
    );
  }
  const responseText = await execution.response.text();
  if (execution.response.status >= 400) {
    return fail(execution.response.status, upstreamErrorBody(responseText) || "ChatGPT Web request failed");
  }
  let content = responseText;
  let resolutionFailed = false;
  try {
    const parsed = JSON.parse(responseText);
    content = String(parsed?.choices?.[0]?.message?.content || "");
    resolutionFailed = parsed?.x_image_resolution_failed === true;
  } catch {
  }
  const urls = Array.from(content.matchAll(IMAGE_MARKDOWN_RE), (match) => match[1]).filter(Boolean);
  if (urls.length === 0) {
    if (RATE_LIMIT_RE.test(content)) return fail(429, content.slice(0, 500));
    return fail(
      502,
      resolutionFailed ? "ChatGPT Web generated an image but its bytes could not be retrieved" : `ChatGPT Web completed without returning image markdown: ${content.slice(0, 300)}`
    );
  }
  const images = [];
  for (const url of urls) {
    const id = url.match(IMAGE_ID_RE)?.[1];
    const cached = id ? getChatGptImage(id) : null;
    if (!cached) return fail(502, "ChatGPT Web image bytes expired before plugin conversion");
    images.push({ base64: cached.bytes.toString("base64"), mime: cached.mime });
  }
  return { success: true, images };
}
async function onImageGeneration(ctx) {
  if (!promptOf(ctx)) return fail(400, "Prompt is required for ChatGPT Web image generation");
  const rawCount = Number.isInteger(ctx.body.n) && Number(ctx.body.n) > 0 ? Number(ctx.body.n) : 1;
  if (rawCount > 4) return fail(400, `ChatGPT Web image generation supports n=1..4 (got ${rawCount})`);
  const images = [];
  for (let index = 0; index < rawCount; index++) {
    const result = await executeForImages(ctx, [{ role: "user", content: generationPrompt(ctx) }]);
    if (!result.success) return result;
    images.push(...result.images);
  }
  return { success: true, images };
}
async function onImageEdit(ctx) {
  if (!promptOf(ctx)) return fail(400, "Prompt is required for ChatGPT Web image edit");
  if (ctx.images.length === 0) return fail(400, "At least one image is required");
  if (ctx.images.length > 4) return fail(400, "ChatGPT Web image edit supports at most four images");
  return executeForImages(ctx, editMessages(ctx));
}
function __setExecutorFactoryForTesting(next) {
  createExecutor = next;
}
export {
  __setExecutorFactoryForTesting,
  onImageEdit,
  onImageGeneration
};
