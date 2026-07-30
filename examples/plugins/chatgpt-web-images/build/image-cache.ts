import { createHash, randomUUID } from "node:crypto";

export interface ChatGptImageConversationContext {
  conversationId: string;
  parentMessageId: string;
}

type CachedImage = {
  bytes: Buffer;
  mime: string;
  expiresAt: number;
  context?: ChatGptImageConversationContext;
  bytesSha256: string;
};

const cache = new Map<string, CachedImage>();
const TTL_MS = 30 * 60_000;
const MAX_ENTRIES = 25;

function purge(): void {
  const now = Date.now();
  for (const [id, entry] of cache) if (entry.expiresAt <= now) cache.delete(id);
  while (cache.size >= MAX_ENTRIES) {
    const oldest = cache.keys().next().value;
    if (!oldest) break;
    cache.delete(oldest);
  }
}

export function storeChatGptImage(
  bytes: Buffer,
  mime: string,
  ttlMs = TTL_MS,
  context?: ChatGptImageConversationContext
): string {
  purge();
  const id = randomUUID().replace(/-/g, "");
  cache.set(id, {
    bytes,
    mime,
    expiresAt: Date.now() + ttlMs,
    context,
    bytesSha256: createHash("sha256").update(bytes).digest("hex"),
  });
  return id;
}

export function getChatGptImage(id: string): CachedImage | null {
  purge();
  return cache.get(id) ?? null;
}

export function getChatGptImageConversationContext(
  id: string
): ChatGptImageConversationContext | null {
  return getChatGptImage(id)?.context ?? null;
}

export function findChatGptImageBySha256(hash: string): { id: string; entry: CachedImage } | null {
  purge();
  for (const [id, entry] of cache) if (entry.bytesSha256 === hash.toLowerCase()) return { id, entry };
  return null;
}

export function __resetChatGptImageCacheForTesting(): void {
  cache.clear();
}

export function __getChatGptImageCacheBytesForTesting(): number {
  return Array.from(cache.values()).reduce((total, entry) => total + entry.bytes.length, 0);
}
