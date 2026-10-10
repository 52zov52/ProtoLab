/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  // The frontend talks to the backend over plain HTTP on loopback only.
  // No remote images, fonts or scripts are loaded: this tool is offline-first.
  images: { unoptimized: true },
  // Next.js 16 blocks dev-resource requests from origins it does not
  // recognise. Both loopback spellings are the analyst's own machine, so they
  // are allowed explicitly; this affects `next dev` only.
  allowedDevOrigins: ["127.0.0.1", "localhost"],
  async headers() {
    return [
      {
        source: "/:path*",
        headers: [
          { key: "X-Content-Type-Options", value: "nosniff" },
          { key: "X-Frame-Options", value: "DENY" },
          { key: "Referrer-Policy", value: "no-referrer" },
          { key: "Cross-Origin-Opener-Policy", value: "same-origin" },
          {
            key: "Content-Security-Policy",
            value: [
              "default-src 'self'",
              "script-src 'self' 'unsafe-inline' 'unsafe-eval'",
              "style-src 'self' 'unsafe-inline'",
              "img-src 'self' data:",
              "font-src 'self' data:",
              "connect-src 'self' http://127.0.0.1:8010 http://localhost:8010",
              "frame-ancestors 'none'",
              "base-uri 'none'",
              "form-action 'self'",
              "object-src 'none'",
            ].join("; "),
          },
        ],
      },
    ];
  },
};

export default nextConfig;