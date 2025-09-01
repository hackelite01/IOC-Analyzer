/** @type {import('next').NextConfig} */
const nextConfig = {
  output: 'standalone',
  serverExternalPackages: ['mongoose'],
  images: {
    remotePatterns: [
      {
        protocol: 'https',
        hostname: '**',
      },
    ],
  },
  env: {
    CUSTOM_KEY: process.env.CUSTOM_KEY,
  },
};

export default nextConfig;
