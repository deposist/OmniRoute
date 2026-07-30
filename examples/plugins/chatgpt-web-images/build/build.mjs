import { existsSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const pluginRoot = resolve(here, "..");
const sourceRoot = resolve(
  process.env.OMNIROUTE_SOURCE || join(pluginRoot, "..", "..", "..", "..", "omniroute-custom-patch", "upstream-v3.8.48")
);
const executor = join(sourceRoot, "open-sse", "executors", "chatgpt-web.ts");
if (!existsSync(executor)) throw new Error(`OmniRoute 3.8.48 source not found: ${executor}`);
const sourceRequire = createRequire(join(sourceRoot, "package.json"));
const { build } = sourceRequire("esbuild");

const aliases = {
  "./base.ts": join(here, "base-shim.ts"),
  "../translator/webTools.ts": join(here, "tool-shim.ts"),
  "./chatgptWebTools.ts": join(here, "tool-shim.ts"),
  "../services/chatgptImageCache.ts": join(here, "image-cache.ts"),
  "../utils/proxyFetch.ts": join(here, "proxy-shim.ts"),
};

await build({
  entryPoints: [join(here, "plugin-entry.ts")],
  outfile: join(pluginRoot, "index.mjs"),
  bundle: true,
  format: "esm",
  platform: "node",
  target: "node22",
  sourcemap: false,
  legalComments: "none",
  external: ["tls-client-node", "undici", "fetch-socks"],
  plugins: [
    {
      name: "standalone-chatgpt-web",
      setup(api) {
        api.onResolve({ filter: /^@omniroute\/chatgpt-web-executor$/ }, () => ({ path: executor }));
        api.onResolve({ filter: /.*/ }, (args) => {
          const replacement = aliases[args.path];
          if (!replacement) return null;
          if (args.path === "./base.ts" && !args.importer.endsWith("chatgpt-web.ts")) return null;
          if (
            args.path === "../utils/proxyFetch.ts" &&
            !args.importer.endsWith("chatgptTlsClient.ts")
          ) return null;
          return { path: replacement };
        });
      },
    },
  ],
});
