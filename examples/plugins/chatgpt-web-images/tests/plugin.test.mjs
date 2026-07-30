import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  __setExecutorFactoryForTesting,
  onImageEdit,
  onImageGeneration,
} from "../index.mjs";

const base = {
  model: "gpt-5.5",
  body: { prompt: "draw a lighthouse" },
  images: [],
  credentials: { apiKey: "cookie" },
  clientHeaders: {},
  config: {},
};

function mockExecutor(capture, options = {}) {
  return () => ({
    async execute(input) {
      capture.push(input);
      if (options.status) {
        return { response: new Response(options.body || "failed", { status: options.status }) };
      }
      const content = options.content || "no image returned";
      return {
        response: new Response(
          JSON.stringify({ choices: [{ message: { content } }] }),
          { status: 200 }
        ),
      };
    },
  });
}

describe("chatgpt-web-images standalone plugin", () => {
  it("does not depend on an OmniRoute host service", async () => {
    const source = await import("node:fs/promises").then((fs) =>
      fs.readFile(new URL("../index.mjs", import.meta.url), "utf8")
    );
    assert.doesNotMatch(source, /__omniroutePluginHost|callService|omniroute-executor/);
    assert.match(source, /tls-client-node/);
  });

  it("runs generation through the bundled provider and preserves requested details", async () => {
    const calls = [];
    __setExecutorFactoryForTesting(mockExecutor(calls));
    const result = await onImageGeneration({
      ...base,
      body: { ...base.body, size: "1024x1024", quality: "high" },
    });
    assert.equal(result.success, false);
    assert.equal(calls.length, 1);
    assert.match(JSON.stringify(calls[0]), /Requested size: 1024x1024/);
    assert.match(JSON.stringify(calls[0]), /Requested quality: high/);
  });

  it("passes one arbitrary image as a data URL", async () => {
    const calls = [];
    __setExecutorFactoryForTesting(mockExecutor(calls));
    const result = await onImageEdit({
      ...base,
      images: [{ base64: Buffer.from("source-one").toString("base64"), mime: "image/jpeg" }],
    });
    assert.equal(result.success, false);
    assert.match(JSON.stringify(calls[0]), /data:image\/jpeg;base64/);
  });

  it("passes all four arbitrary images and rejects a fifth", async () => {
    const calls = [];
    __setExecutorFactoryForTesting(mockExecutor(calls));
    const images = Array.from({ length: 4 }, (_, index) => ({
      base64: Buffer.from(`source-${index}`).toString("base64"),
      mime: "image/png",
    }));
    const result = await onImageEdit({ ...base, images });
    assert.equal(result.success, false);
    assert.equal((JSON.stringify(calls[0]).match(/data:image\/png;base64/g) || []).length, 4);
    const rejected = await onImageEdit({ ...base, images: [...images, images[0]] });
    assert.deepEqual(rejected, {
      success: false,
      status: 400,
      error: "ChatGPT Web image edit supports at most four images",
    });
  });

  it("preserves upstream status and message", async () => {
    __setExecutorFactoryForTesting(
      mockExecutor([], { status: 403, body: JSON.stringify({ error: { message: "Sentinel blocked" } }) })
    );
    assert.deepEqual(await onImageGeneration(base), {
      success: false,
      status: 403,
      error: "Sentinel blocked",
    });
  });

  it("maps ChatGPT image limits to 429", async () => {
    __setExecutorFactoryForTesting(
      mockExecutor([], { content: "You've hit your image generation limit" })
    );
    const result = await onImageGeneration(base);
    assert.equal(result.success, false);
    if (!result.success) assert.equal(result.status, 429);
  });

  it("keeps recursive pointer traversal guarded", async () => {
    const source = await import("node:fs/promises").then((fs) =>
      fs.readFile(new URL("../index.mjs", import.meta.url), "utf8")
    );
    assert.match(source, /depth > 64/);
    assert.match(source, /new WeakSet/);
    assert.match(source, /ArrayBuffer\.isView/);
  });
});
