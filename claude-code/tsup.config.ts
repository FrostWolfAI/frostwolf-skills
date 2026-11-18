import { defineConfig } from "tsup";
import pkg from "./package.json";

// Every entry is bundled with its dependencies, because a plugin is copied into
// place as it is and has no install step to fetch them. `hook` and `daemon` run
// under Claude Code, Codex, and Cursor; `opencode` is loaded by OpenCode itself.
export default defineConfig({
  entry: {
    hook: "src/hook-main.ts",
    daemon: "src/daemon-main.ts",
    opencode: "src/opencode/plugin.ts",
  },
  format: ["esm"],
  outExtension: () => ({ js: ".mjs" }),
  platform: "node",
  target: "node18",
  clean: true,
  splitting: false,
  noExternal: [/.*/],
  define: { __PLUGIN_VERSION__: JSON.stringify(pkg.version) },
});
