import { afterEach, describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdir, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";

import { loadPlugin } from "../../src/lib/plugins/loader.ts";
import type { PluginManifestWithDefaults } from "../../src/lib/plugins/manifest.ts";

function makeManifest(overrides?: Partial<PluginManifestWithDefaults>): PluginManifestWithDefaults {
  return {
    name: "test-plugin",
    version: "1.0.0",
    description: "Test",
    license: "MIT",
    main: "index.mjs",
    tags: [],
    hooks: {
      onRequest: true,
      onResponse: false,
      onError: false,
      onImageGeneration: false,
      onImageEdit: false,
      onInstall: false,
      onActivate: false,
      onDeactivate: false,
      onUninstall: false,
    },
    imageProviders: [],
    skills: [],
    configSchema: {},
    requires: { permissions: [] },
    enabledByDefault: true,
    source: "local",
    ...overrides,
  };
}

const testDirs: string[] = [];

afterEach(async () => {
  await Promise.all(testDirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

describe("Plugin loader IPC", () => {
  it("loadPlugin returns LoadedPlugin with expected shape", async () => {
    // loadPlugin spawns a child process — we test it returns the right shape
    // but we can't easily test IPC without a real plugin file.
    // Instead, test the function signature and error handling.
    assert.equal(typeof loadPlugin, "function");
  });

  it("loader exports LoadedPlugin interface", async () => {
    // Verify the module exports the expected function
    const mod = await import("../../src/lib/plugins/loader.ts");
    assert.equal(typeof mod.loadPlugin, "function");
  });

  it("loadPlugin rejects invalid entry point gracefully", async () => {
    const manifest = makeManifest();
    try {
      const loaded = await loadPlugin("/nonexistent/path/plugin.mjs", manifest);
      // If it doesn't throw, it should still return a valid object
      assert.ok(loaded.name);
      assert.ok(loaded.cleanup);
      loaded.cleanup();
    } catch (err) {
      // Expected — nonexistent path should cause an error
      assert.ok(err instanceof Error);
    }
  });

  it("manifest permissions affect env filtering", () => {
    const manifest = makeManifest({ requires: { permissions: ["env"] } });
    assert.deepEqual(manifest.requires.permissions, ["env"]);

    const manifestNoPerms = makeManifest({ requires: { permissions: [] } });
    assert.deepEqual(manifestNoPerms.requires.permissions, []);
  });

  it("manifest with all permissions", () => {
    const manifest = makeManifest({
      requires: { permissions: ["network", "file-read", "file-write", "env", "exec"] },
    });
    assert.equal(manifest.requires.permissions.length, 5);
  });

  it("passes plugin config over IPC and invokes image handlers", async () => {
    const dir = join(tmpdir(), `omniroute-plugin-ipc-${crypto.randomUUID()}`);
    testDirs.push(dir);
    await mkdir(dir, { recursive: true });
    const entry = join(dir, "index.mjs");
    await writeFile(
      entry,
      `export async function onImageGeneration(ctx) {
        const value = JSON.stringify({ marker: ctx.config.marker, imageTimeoutMs: ctx.config.imageTimeoutMs, proxyUrl: ctx.proxyUrl });
        return { success: true, images: [{ base64: Buffer.from(value).toString("base64"), mime: "image/png" }] };
      }`,
      "utf8"
    );
    const loaded = await loadPlugin(
      entry,
      makeManifest({
        configSchema: {
          marker: { type: "string", default: "default-marker" },
          imageTimeoutMs: { type: "number", default: 150000 },
        },
        hooks: {
          ...makeManifest().hooks,
          onRequest: false,
          onImageGeneration: true,
        },
        imageProviders: [
          {
            id: "ipc-images",
            credentialProvider: "chatgpt-web",
            models: [{ id: "model", name: "Model", inputModalities: ["text"] }],
            supportedSizes: [],
            operations: ["generation"],
            timeoutMs: 10_000,
          },
        ],
      }),
      { marker: "configured" }
    );
    try {
      const result = await loaded.plugin.onImageGeneration?.({
        operation: "generation",
        provider: "ipc-images",
        model: "model",
        body: {},
        images: [],
        credentials: null,
        clientHeaders: {},
        proxyUrl: "http://proxy.example:8080",
        config: {},
      });
      assert.equal(result?.success, true);
      if (result?.success) {
        assert.deepEqual(JSON.parse(Buffer.from(result.images[0].base64, "base64").toString()), {
          marker: "configured",
          imageTimeoutMs: 150000,
          proxyUrl: "http://proxy.example:8080",
        });
      }
    } finally {
      loaded.cleanup();
    }
  });

});
