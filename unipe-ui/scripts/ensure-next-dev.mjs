#!/usr/bin/env node
// tauri beforeDevCommand: reuse an existing next server on :3000, otherwise start one.
import { createServer } from "node:net";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const PORT = Number(process.env.PORT || 3000);
const root = join(dirname(fileURLToPath(import.meta.url)), "..");

function portTaken(port) {
  return new Promise((resolve) => {
    const server = createServer();
    server.once("error", () => resolve(true));
    server.once("listening", () => {
      server.close(() => resolve(false));
    });
    server.listen(port, "127.0.0.1");
  });
}

if (await portTaken(PORT)) {
  console.log(`next already listening on :${PORT}, reusing it`);
  // exit 0 so tauri keeps going and waits for devUrl
  process.exit(0);
}

const child = spawn("npm", ["run", "dev"], {
  cwd: root,
  stdio: "inherit",
  env: process.env,
  shell: process.platform === "win32",
});

child.on("exit", (code, signal) => {
  if (signal) process.exit(1);
  process.exit(code ?? 1);
});
