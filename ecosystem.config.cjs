// PM2: pm2 start ecosystem.config.cjs && pm2 save
module.exports = {
  apps: [
    {
      name: 'shieldops-api',
      script: 'dist/server.js',
      cwd: __dirname,
      // One process: rate limits live in memory. The scheduler claims work atomically, so a second process would be safe for checks.
      instances: 1,
      exec_mode: 'fork',
      max_memory_restart: '512M',
      env: { NODE_ENV: 'production' },
      time: true,
      kill_timeout: 12000,
    },
  ],
};