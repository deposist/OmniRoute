type ImageInput = { base64: string; mime: string };
type PluginContext = {
  model: string;
  body: Record<string, unknown>;
  images: ImageInput[];
  credentials: Record<string, unknown> | null;
  clientHeaders: Record<string, string>;
  proxyUrl?: string | null;
  config: Record<string, unknown>;
};
type PluginResult =
  | { success: true; images: Array<{ base64: string; mime: string }> }
  | { success: false; status: number; error: string };
type ExecuteResult = { response: Response };
type Executor = { execute(input: Record<string, unknown>): Promise<ExecuteResult> };
type ExecutorFactory = () => Executor;

import { ChatGptWebExecutor } from "@omniroute/chatgpt-web-executor";
import { getChatGptImage } from "./image-cache.ts";
import { setPluginProxyUrl } from "./proxy-shim.ts";

let createExecutor: ExecutorFactory = () => new ChatGptWebExecutor() as Executor;

const IMAGE_MARKDOWN_RE = /!\[[^\]]*\]\(([^)\s]+)\)/g;
const IMAGE_ID_RE = /\/v1\/chatgpt-web\/image\/([a-f0-9]{16,64})(?=[?\s"'<>)]|$)/i;
const RATE_LIMIT_RE =
  /you.ve hit the.*plan limit for image|you.ve hit your image generation limit|image generation.*limit.*reset|limit resets in|create more images when the limit|reached the.*limit.*image/i;

function fail(status: number, error: string): PluginResult {
  return { success: false, status, error };
}

function promptOf(ctx: PluginContext): string {
  return typeof ctx.body.prompt === "string" ? ctx.body.prompt.trim() : "";
}

function credentialsOf(ctx: PluginContext): Record<string, unknown> | null {
  return ctx.credentials && typeof ctx.credentials.apiKey === "string" && ctx.credentials.apiKey
    ? ctx.credentials
    : null;
}

function numberConfig(ctx: PluginContext, key: string): string | null {
  const value = ctx.config[key];
  return typeof value === "number" && Number.isFinite(value) && value > 0
    ? String(Math.floor(value))
    : null;
}

function configureRuntime(ctx: PluginContext): void {
  setPluginProxyUrl(
    typeof ctx.proxyUrl === "string" && ctx.proxyUrl.trim()
      ? ctx.proxyUrl.trim()
      : typeof ctx.config.proxyUrl === "string" && ctx.config.proxyUrl.trim()
        ? ctx.config.proxyUrl.trim()
      : null
  );
  for (const [configKey, envKey] of [
    ["imageTimeoutMs", "OMNIROUTE_CGPT_WEB_IMAGE_TIMEOUT_MS"],
    ["imageWsTimeoutMs", "OMNIROUTE_CGPT_WEB_IMAGE_WS_TIMEOUT_MS"],
    ["proTimeoutMs", "OMNIROUTE_CGPT_WEB_PRO_TIMEOUT_MS"],
  ] as const) {
    const value = numberConfig(ctx, configKey);
    if (value) process.env[envKey] = value;
    else delete process.env[envKey];
  }
}

function generationPrompt(ctx: PluginContext): string {
  const details = [`Create an image for this prompt: ${promptOf(ctx)}`];
  for (const [label, key] of [
    ["Requested size", "size"],
    ["Requested quality", "quality"],
    ["Requested style", "style"],
  ] as const) {
    const value = ctx.body[key];
    if (typeof value === "string" && value.trim()) details.push(`${label}: ${value.trim()}.`);
  }
  return details.join("\n");
}

function editMessages(ctx: PluginContext): Array<{ role: string; content: unknown }> {
  return [
    {
      role: "user",
      content: [
        {
          type: "text",
          text: `Edit the attached image(s) and generate the new image: ${promptOf(ctx)}`,
        },
        ...ctx.images.slice(0, 4).map((image) => ({
          type: "image_url",
          image_url: { url: `data:${image.mime};base64,${image.base64}` },
        })),
      ],
    },
  ];
}

function upstreamErrorBody(text: string): string {
  try {
    const parsed = JSON.parse(text);
    return String(parsed?.error?.message || parsed?.error || text);
  } catch {
    return text;
  }
}

async function executeForImages(
  ctx: PluginContext,
  messages: Array<{ role: string; content: unknown }>
): Promise<PluginResult> {
  const credentials = credentialsOf(ctx);
  if (!credentials) return fail(401, "ChatGPT Web credentials missing session cookie");
  configureRuntime(ctx);

  let execution: ExecuteResult;
  try {
    execution = await createExecutor().execute({
      model: ctx.model,
      body: { messages },
      stream: false,
      credentials,
      clientHeaders: ctx.clientHeaders,
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
  } catch {}

  const urls = Array.from(content.matchAll(IMAGE_MARKDOWN_RE), (match) => match[1]).filter(Boolean);
  if (urls.length === 0) {
    if (RATE_LIMIT_RE.test(content)) return fail(429, content.slice(0, 500));
    return fail(
      502,
      resolutionFailed
        ? "ChatGPT Web generated an image but its bytes could not be retrieved"
        : `ChatGPT Web completed without returning image markdown: ${content.slice(0, 300)}`
    );
  }

  const images: Array<{ base64: string; mime: string }> = [];
  for (const url of urls) {
    const id = url.match(IMAGE_ID_RE)?.[1];
    const cached = id ? getChatGptImage(id) : null;
    if (!cached) return fail(502, "ChatGPT Web image bytes expired before plugin conversion");
    images.push({ base64: cached.bytes.toString("base64"), mime: cached.mime });
  }
  return { success: true, images };
}

export async function onImageGeneration(ctx: PluginContext): Promise<PluginResult> {
  if (!promptOf(ctx)) return fail(400, "Prompt is required for ChatGPT Web image generation");
  const rawCount = Number.isInteger(ctx.body.n) && Number(ctx.body.n) > 0 ? Number(ctx.body.n) : 1;
  if (rawCount > 4) return fail(400, `ChatGPT Web image generation supports n=1..4 (got ${rawCount})`);

  const images: Array<{ base64: string; mime: string }> = [];
  for (let index = 0; index < rawCount; index++) {
    const result = await executeForImages(ctx, [{ role: "user", content: generationPrompt(ctx) }]);
    if (!result.success) return result;
    images.push(...result.images);
  }
  return { success: true, images };
}

export async function onImageEdit(ctx: PluginContext): Promise<PluginResult> {
  if (!promptOf(ctx)) return fail(400, "Prompt is required for ChatGPT Web image edit");
  if (ctx.images.length === 0) return fail(400, "At least one image is required");
  if (ctx.images.length > 4) return fail(400, "ChatGPT Web image edit supports at most four images");
  return executeForImages(ctx, editMessages(ctx));
}

export function __setExecutorFactoryForTesting(next: ExecutorFactory): void {
  createExecutor = next;
}
