import { defineConfig } from "vitest/config";
import pkg from "./package.json";

export default defineConfig({
  define: { __PLUGIN_VERSION__: JSON.stringify(pkg.version) },
  test: {
    include: ["test/**/*.test.ts"],
  },
});
