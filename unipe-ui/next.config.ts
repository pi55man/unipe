import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // tauri loads a static build from /out — no next server in the shipped app
  output: "export",
  images: { unoptimized: true },
};

export default nextConfig;
