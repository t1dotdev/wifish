import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.dirname(fileURLToPath(import.meta.url));

/** @type {import('next').NextConfig} */
const nextConfig = {
  // Production verification must not overwrite a running dev server's chunks.
  distDir: process.env.NODE_ENV === 'development' ? '.next-dev' : '.next',
  experimental: { largePageDataBytes: 512 * 1024 },
  // '@/' -> repo root. Set explicitly: TS 7 removed baseUrl, which Next 15's
  // tsconfig-paths support relied on.
  webpack: (config) => {
    config.resolve.alias['@'] = root;
    return config;
  },
};
export default nextConfig;
