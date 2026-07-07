import { build } from "vite";
import { rm } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

// Resolve paths from this script so the build works from any caller working directory.
const projectRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const webRoot = resolve(projectRoot, "web");
const outDir = resolve(projectRoot, "dist");

// Keep production builds independent from Vite config loading so the project
// builds reliably from Windows paths with spaces and non-ASCII characters.
await rm(outDir, { recursive: true, force: true });
await build({
  configFile: false,
  root: webRoot,
  publicDir: resolve(webRoot, "public"),
  build: {
    outDir,
    emptyOutDir: false,
    minify: "esbuild"
  }
});
