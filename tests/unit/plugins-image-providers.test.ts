import { afterEach, describe, it } from "node:test";
import assert from "node:assert/strict";

import {
  getAllPluginImageModels,
  getPluginImageProvider,
  normalizePluginImageResult,
  parsePluginImageModel,
  registerPluginImageProvider,
  resetPluginImageProviders,
  unregisterPluginImageProviders,
} from "../../src/lib/plugins/imageProviders.ts";

const provider = {
  pluginName: "test-images",
  id: "test-images",
  alias: "ti",
  credentialProvider: "chatgpt-web",
  models: [
    {
      id: "model-1",
      name: "Model 1",
      inputModalities: ["text", "image"] as Array<"text" | "image">,
    },
  ],
  supportedSizes: ["1024x1024"],
  operations: ["generation", "edit"] as Array<"generation" | "edit">,
  timeoutMs: 180_000,
  generate: async () => ({ success: true as const, images: [] }),
  edit: async () => ({ success: true as const, images: [] }),
};

afterEach(resetPluginImageProviders);

describe("plugin image-provider registry", () => {
  it("registers provider ids, aliases and catalog models", () => {
    registerPluginImageProvider(provider);

    assert.equal(getPluginImageProvider("test-images")?.pluginName, "test-images");
    assert.equal(getPluginImageProvider("ti")?.id, "test-images");
    assert.equal(parsePluginImageModel("ti/model-1")?.model.id, "model-1");
    assert.deepEqual(getAllPluginImageModels(), [
      {
        id: "test-images/model-1",
        name: "Model 1",
        provider: "test-images",
        supportedSizes: ["1024x1024"],
        inputModalities: ["text", "image"],
        description: undefined,
      },
    ]);
  });

  it("unregisters all provider metadata owned by a plugin", () => {
    registerPluginImageProvider(provider);
    unregisterPluginImageProviders("test-images");

    assert.equal(getPluginImageProvider("test-images"), null);
    assert.equal(getPluginImageProvider("ti"), null);
    assert.deepEqual(getAllPluginImageModels(), []);
  });

  it("rejects provider and alias collisions", () => {
    registerPluginImageProvider(provider);

    assert.throws(
      () => registerPluginImageProvider({ ...provider, id: "other", alias: "ti", pluginName: "other" }),
      /already registered/
    );
    assert.throws(
      () => registerPluginImageProvider({ ...provider, id: "ti", alias: undefined, pluginName: "other" }),
      /conflicts with alias/
    );
  });

  it("normalizes plugin failures and rejects malformed image data", () => {
    assert.deepEqual(normalizePluginImageResult({ success: false, status: 429, error: "limit" }), {
      success: false,
      status: 429,
      error: "limit",
    });
    assert.deepEqual(normalizePluginImageResult({ success: true, images: [] }), {
      success: false,
      status: 502,
      error: "Image plugin returned no images",
    });
    assert.deepEqual(
      normalizePluginImageResult({
        success: true,
        images: [{ base64: Buffer.from("image").toString("base64"), mime: "image/png" }],
      }),
      {
        success: true,
        images: [{ base64: Buffer.from("image").toString("base64"), mime: "image/png" }],
      }
    );
  });
});
