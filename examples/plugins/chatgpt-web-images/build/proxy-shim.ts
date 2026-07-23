import { ProxyAgent, WebSocket as UndiciWebSocket, fetch as undiciFetch } from "undici";
import { socksDispatcher } from "fetch-socks";

let pluginProxyUrl: string | null = null;
const originalFetch = globalThis.fetch.bind(globalThis);
const originalWebSocket = globalThis.WebSocket;

function dispatcherFor(proxyUrl: string): object {
  const parsed = new URL(proxyUrl);
  if (parsed.protocol === "socks5:") {
    return socksDispatcher({
      type: 5,
      host: parsed.hostname,
      port: Number(parsed.port || 1080),
      ...(parsed.username ? { userId: decodeURIComponent(parsed.username) } : {}),
      ...(parsed.password ? { password: decodeURIComponent(parsed.password) } : {}),
    });
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error(`Unsupported plugin proxy protocol: ${parsed.protocol}`);
  }
  return new ProxyAgent(proxyUrl);
}

function installNetworkAdapters(): void {
  globalThis.fetch = (async (input: RequestInfo | URL, init: RequestInit = {}) => {
    if (!pluginProxyUrl) return originalFetch(input, init);
    return undiciFetch(input, {
      ...init,
      dispatcher: dispatcherFor(pluginProxyUrl),
    } as Parameters<typeof undiciFetch>[1]) as unknown as Promise<Response>;
  }) as typeof globalThis.fetch;

  globalThis.WebSocket = function PluginProxyWebSocket(
    url: string | URL,
    protocols?: string | string[]
  ) {
    if (!pluginProxyUrl) return new originalWebSocket(url, protocols);
    return new UndiciWebSocket(url, {
      ...(protocols ? { protocols } : {}),
      dispatcher: dispatcherFor(pluginProxyUrl),
    });
  } as unknown as typeof globalThis.WebSocket;
}

export function setPluginProxyUrl(value: string | null): void {
  pluginProxyUrl = value;
  installNetworkAdapters();
}

export function resolveProxyForRequest(_targetUrl: string): {
  source: string;
  proxyUrl: string | null;
} {
  return pluginProxyUrl
    ? { source: "plugin-context", proxyUrl: pluginProxyUrl }
    : { source: "direct", proxyUrl: null };
}
