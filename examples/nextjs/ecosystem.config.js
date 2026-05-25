// PM2 ecosystem file for running a licensed Next.js app on GB10
// bare metal (no Docker). Use together with the systemd unit at
// `examples/nextjs/license-app.service` so PM2 itself comes back up
// after reboot.
//
// Usage on the device:
//
//   # one-time
//   sudo npm i -g pm2
//   cd /www/wwwroot/jw
//   npm ci && npm run build
//   # standalone 需额外同步静态资源（build 后执行一次）：
//   cp -r .next/static .next/standalone/.next/static
//   pm2 start ecosystem.config.js
//   pm2 save                       # snapshot current process list
//
// next.config.ts 使用 output: 'standalone'，生产环境应运行
// `.next/standalone/server.js`，不要用 `npm start`（tsx server.ts）或
// `next start`——否则会触发 standalone 不兼容警告。
//
//   # systemd hand-off (recommended over `pm2 startup` so we control
//   # the User=, capabilities and the license env file ourselves):
//   sudo cp examples/nextjs/license-app.service /etc/systemd/system/
//   sudo systemctl daemon-reload
//   sudo systemctl enable --now license-app
//
// Why we run as root:
//   The hardware fingerprint hashes /sys/class/dmi/id/{product_uuid,
//   product_serial,board_serial}. On GB10 (and most Linux servers)
//   these sysfs nodes are mode 0400 owned by root. Skipping them
//   produces a *different* fingerprint than the one issued via
//   `sudo ./build/issuer sign -local`, so verification fails with
//   `fingerprint_mismatch`.
//
//   Two acceptable alternatives (only if you really cannot run as
//   root): see `examples/nextjs/README.md` → "Running unprivileged".

module.exports = {
  apps: [
    {
      name: 'nextjs-app',
      // standalone 入口：server.js 内部会 process.chdir(__dirname)
      cwd: '/www/wwwroot/jw/.next/standalone',
      script: 'server.js',
      interpreter: 'node',
      // Match the box (4 cores on GB10's Grace CPUs is plenty for most
      // dashboards; bump if you actually serve heavy traffic).
      instances: 1,
      exec_mode: 'fork',
      autorestart: true,
      // EX_CONFIG (78) means "license invalid" — keep restarting
      // because the operator may be in the middle of dropping the new
      // license.json into /opt/your-app/license/. After ~30 attempts
      // PM2 enters cooldown; alert your monitoring on it.
      max_restarts: 30,
      restart_delay: 10_000,
      // Logs end up under /root/.pm2/logs/ when run via systemd.
      // Symlink them to your usual place if you want.
      out_file: '/var/log/nextjs-app.out.log',
      error_file: '/var/log/nextjs-app.err.log',
      merge_logs: true,
      time: true,

      env: {
        NODE_ENV: 'production',
        NODE_OPTIONS: '--expose-gc',
        PORT: '3006',
        HOSTNAME: '0.0.0.0',
        // standalone server.js 读取 KEEP_ALIVE_TIMEOUT（毫秒）；对齐原 server.ts 默认 905s
        KEEP_ALIVE_TIMEOUT: '905000',

        // ----- License & key material -----
        LICENSE_PATH: '/www/wwwroot/jw/license/license.json',
        LICENSE_PUBLIC_KEY: '/www/wwwroot/jw/license/public.pem',
        LICENSE_WATERMARK: '/www/wwwroot/jw/license/.watermark',
        LICENSE_RECHECK_MS: String(60 * 60 * 1000), // hourly

        // ----- Hardware fingerprint inputs -----
        // HW_CONTAINER intentionally NOT set — bare metal default
        // (/sys/class/dmi/id, /proc/cmdline, /sys/class/net, ...).
        HW_NIC: 'enP7s7',     // <-- replace with `ip -o link show` output
        HW_DISK: 'nvme0n1',   // <-- replace with `ls /sys/class/block | grep nvme`
        HW_NVIDIA_SMI: 'nvidia-smi',
        HW_REQUIRE_GPU: '1',
      },
    },
  ],
};
