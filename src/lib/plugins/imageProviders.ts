/**
 * Runtime registry for image providers contributed by external plugins.
 *
 * The registry intentionally contains only serializable provider metadata and
 * handler functions. Authentication, API-key policy, proxy selection, account
 * health and HTTP response shaping remain owned by the image routes.
 */

export type PluginImageOperation = "generation" | "edit";

export interface PluginImageModel {
  id: string;
  name: string;
  inputModalities: Array<"text" | "image">;
  description?: string;
}

export interface PluginImageProviderDefinition {
  id: string;
  alias?: string;
  credentialProvider: string;
  models: PluginImageModel[];
  supportedSizes: string[];
  operations: PluginImageOperation[];
  timeoutMs: number;
}

export interface PluginImageInput {
  base64: string;
  mime: string;
}

export interface PluginImageRequestContext {
  operation: PluginImageOperation;
  provider: string;
  model: string;
  body: Record<string, unknown>;
  images: PluginImageInput[];
  credentials: Record<string, unknown> | null;
  clientHeaders: Record<string, string>;
  proxyUrl?: string | null;
  config: Record<string, unknown>;
}

export type PluginImageResult =
  | {
      success: true;
      images: Array<{ base64: string; mime: string }>;
    }
  | {
      success: false;
      status: number;
      error: string;
    };

export type PluginImageHandler = (
  ctx: PluginImageRequestContext
) => Promise<PluginImageResult> | PluginImageResult;

export interface RegisteredPluginImageProvider extends PluginImageProviderDefinition {
  pluginName: string;
  generate?: PluginImageHandler;
  edit?: PluginImageHandler;
}

const providers = new Map<string, RegisteredPluginImageProvider>();
const aliases = new Map<string, string>();

export function registerPluginImageProvider(provider: RegisteredPluginImageProvider): void {
  const previous = providers.get(provider.id);
  if (previous && previous.pluginName !== provider.pluginName) {
    throw new Error(
      `Image provider '${provider.id}' is already registered by plugin '${previous.pluginName}'`
    );
  }
  const providerIdAliasTarget = aliases.get(provider.id);
  if (providerIdAliasTarget && providerIdAliasTarget !== provider.id) {
    throw new Error(
      `Image provider id '${provider.id}' conflicts with alias owned by '${providerIdAliasTarget}'`
    );
  }
  if (provider.alias) {
    const aliasProvider = providers.get(provider.alias);
    if (aliasProvider && aliasProvider.id !== provider.id) {
      throw new Error(
        `Image provider alias '${provider.alias}' conflicts with provider '${aliasProvider.id}'`
      );
    }
    const aliasTarget = aliases.get(provider.alias);
    if (aliasTarget && aliasTarget !== provider.id) {
      throw new Error(
        `Image provider alias '${provider.alias}' is already registered for '${aliasTarget}'`
      );
    }
  }
  if (previous?.alias) aliases.delete(previous.alias);
  providers.set(provider.id, provider);
  if (provider.alias) aliases.set(provider.alias, provider.id);
}

export function unregisterPluginImageProviders(pluginName: string): void {
  for (const [providerId, provider] of providers.entries()) {
    if (provider.pluginName !== pluginName) continue;
    providers.delete(providerId);
    for (const [alias, target] of aliases.entries()) {
      if (target === providerId) aliases.delete(alias);
    }
  }
}

export function getPluginImageProvider(
  providerIdOrAlias: string
): RegisteredPluginImageProvider | null {
  const providerId = aliases.get(providerIdOrAlias) ?? providerIdOrAlias;
  return providers.get(providerId) ?? null;
}

export function parsePluginImageModel(
  modelStr: string
): { provider: RegisteredPluginImageProvider; model: PluginImageModel } | null {
  if (!modelStr) return null;
  const slash = modelStr.indexOf("/");
  if (slash > 0) {
    const provider = getPluginImageProvider(modelStr.slice(0, slash));
    const modelId = modelStr.slice(slash + 1);
    const model = provider?.models.find((entry) => entry.id === modelId);
    return provider && model ? { provider, model } : null;
  }
  for (const provider of providers.values()) {
    const model = provider.models.find((entry) => entry.id === modelStr);
    if (model) return { provider, model };
  }
  return null;
}

export function getAllPluginImageModels() {
  return Array.from(providers.values()).flatMap((provider) =>
    provider.models.map((model) => ({
      id: `${provider.id}/${model.id}`,
      name: model.name,
      provider: provider.id,
      supportedSizes: provider.supportedSizes,
      inputModalities: model.inputModalities,
      description: model.description,
    }))
  );
}

export function resetPluginImageProviders(): void {
  providers.clear();
  aliases.clear();
}

export function normalizePluginImageResult(value: unknown): PluginImageResult {
  if (!value || typeof value !== "object") {
    return { success: false, status: 502, error: "Image plugin returned an invalid result" };
  }
  const result = value as Record<string, unknown>;
  if (result.success === false) {
    const status = Number(result.status);
    return {
      success: false,
      status: Number.isInteger(status) && status >= 400 && status <= 599 ? status : 502,
      error:
        typeof result.error === "string" && result.error.trim()
          ? result.error
          : "Image plugin failed without an error message",
    };
  }
  if (result.success !== true || !Array.isArray(result.images) || result.images.length === 0) {
    return { success: false, status: 502, error: "Image plugin returned no images" };
  }
  const images: Array<{ base64: string; mime: string }> = [];
  for (const image of result.images) {
    if (!image || typeof image !== "object") {
      return { success: false, status: 502, error: "Image plugin returned an invalid image" };
    }
    const candidate = image as Record<string, unknown>;
    if (
      typeof candidate.base64 !== "string" ||
      candidate.base64.length === 0 ||
      !/^[A-Za-z0-9+/]+={0,2}$/.test(candidate.base64) ||
      typeof candidate.mime !== "string" ||
      !/^image\/[a-z0-9.+-]+$/i.test(candidate.mime)
    ) {
      return { success: false, status: 502, error: "Image plugin returned invalid image data" };
    }
    images.push({ base64: candidate.base64, mime: candidate.mime });
  }
  return { success: true, images };
}
