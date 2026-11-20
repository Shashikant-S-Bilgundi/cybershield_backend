// PM2: pm2 start ecosystem.config.cjs && pm2 save
module.exports = {
  apps: [
    {
      name: 'shieldops-api',
      script: 'dist/server.js',
      cwd: __dirname,
      // One process: rate limits and the daily maintenance job live in memory. Scale out only after moving them to Redis.
      instances: 1,
      exec_mode: 'fork',
      max_memory_restart: '512M',
      env: { NODE_ENV: 'production' },
      time: true,
      kill_timeout: 12000,
    },
  ],
};