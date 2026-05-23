// Minimum Next.js config to enable instrumentation.ts. Next.js 14+
// has instrumentation on by default, so this file is only needed on
// older 13.x apps.

/** @type {import('next').NextConfig} */
module.exports = {
  experimental: {
    instrumentationHook: true,
  },
};
