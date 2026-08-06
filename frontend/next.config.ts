import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  async rewrites() {
    return [
      {
        source: '/api/aegis-raw/:path*',
        destination: 'http://localhost:8080/:path*',
      },
      {
        source: '/api/nexus-raw/:path*',
        destination: 'http://localhost:5173/:path*',
      },
      {
        source: '/assets/:path*',
        destination: 'http://localhost:5173/assets/:path*',
      },
      {
        source: '/api/:path*',
        destination: 'http://localhost:8000/api/:path*',
      },
    ]
  },
};

export default nextConfig;
