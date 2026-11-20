// Test configuration: a throwaway database on the local MongoDB.
process.env.NODE_ENV = 'test';
process.env.MONGODB_URI = process.env.TEST_MONGODB_URI ?? 'mongodb://127.0.0.1:27017/shieldops_test';
process.env.APP_URL = 'http://localhost:5173';
process.env.ENCRYPTION_KEY = Buffer.alloc(32, 7).toString('base64');
process.env.COOKIE_SECURE = 'false';
process.env.TRUST_PROXY = '0';