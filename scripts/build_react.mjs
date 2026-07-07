import { build } from "vite";
import { rm } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

// 어떤 작업 디렉터리에서 호출해도 빌드가 동작하도록 이 스크립트 기준으로 경로를 풉니다.
const projectRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const webRoot = resolve(projectRoot, "web");
const outDir = resolve(projectRoot, "dist");

// 공백과 비ASCII 문자가 있는 Windows 경로에서도 안정적으로 빌드되도록
// 운영 빌드는 Vite 설정 로딩과 분리합니다.
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
