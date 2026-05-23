# Next.js integration example

1. Add the verifier package to your Next.js project:

   ```bash
   # Option A: from a local checkout of this repo
   cd verifier-node && npm run build && npm pack
   cd ../examples/nextjs && npm install ../verifier-node/yourorg-license-verifier-1.0.0.tgz

   # Option B: publish to your internal registry, then
   npm install @yourorg/license-verifier
   ```

2. Drop [`instrumentation.ts`](./instrumentation.ts) at the **root** of
   your Next.js project (same level as `next.config.js`).

3. If you are on Next.js 13.x add the snippet from
   [`next.config.example.js`](./next.config.example.js) to your
   existing config. Next.js 14+ has the hook enabled by default.

4. Build the app into a Docker image and arrange for the following
   bind mounts (see `docker-compose.yml` at repo root):

   | container path | source                       | mode |
   |----------------|------------------------------|------|
   | `/license/`    | `./license/` on host         | rw   |
   | `/host/dmi`    | `/sys/class/dmi/id`          | ro   |
   | `/host/dt`     | `/proc/device-tree`          | ro   |
   | `/host/net`    | `/sys/class/net`             | ro   |
   | `/host/cmdline`| `/proc/cmdline`              | ro   |

5. Drop a freshly issued `license.json` and the matching `public.pem`
   into `./license/` on the host before starting the container. The
   `.watermark` file is created on first successful verification and
   then maintained by the app itself.

6. The container's startup will write a single JSON log line per
   verification attempt. On failure it exits with code `78`; configure
   your supervisor (systemd / Docker `restart: on-failure`) accordingly.
