import { defineConfig } from "tsup";
import pkg from "./package.json";

// Both entries are bundled with their dependencies, because a plugin is copied
// into place as it is and has no install step to fetch them.
export default defineConfig({
  entry: { hook: "src/hook-main.ts", daemon: "src/daemon-main.ts" },
  format: ["esm"],
  outExtension: () => ({ js: ".mjs" }),
  platform: "node",
  target: "node18",
  clean: true,
  splitting: false,
  noExternal: [/.*/],
  define: { __PLUGIN_VERSION__: JSON.stringify(pkg.version) },
});
