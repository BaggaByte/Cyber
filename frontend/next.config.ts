import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  output: 'standalone',
  // Rewrite /api/* -> FastAPI backend (works inside Docker via service name)
  async rewrites() {
    const backendUrl = process.env.NEXT_PUBLIC_API_URL || "http://api:8000";
    const aegisUrl = process.env.AEGIS_URL || "http://aegis-backend:8001";
    return {
      fallback: [
        {
          source: "/api/:path*",
          destination: `${backendUrl}/:path*`,
        },
        {
          source: "/aegis-api/:path*",
          destination: `${aegisUrl}/:path*`,
        },
      ]
    };
  },
};

export default nextConfig;
