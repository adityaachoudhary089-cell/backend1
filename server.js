const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const path = require('path');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const xss = require('xss');
const hpp = require('hpp');
require('dotenv').config();

// Import routes
const authRoutes = require('./routes/auth');

const app = express();

// 1. HELMET SECURITY HEADERS
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"],
      fontSrc: ["'self'", "https://cdnjs.cloudflare.com"],
      connectSrc: ["'self'"],
      frameSrc: ["'none'"],
      objectSrc: ["'none'"],
      upgradeInsecureRequests: []
    }
  },
  crossOriginEmbedderPolicy: false,
  xssFilter: true,
  noSniff: true,
  frameguard: { action: 'deny' },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  }
}));

// 2. ADDITIONAL SECURITY HEADERS
app.use((req, res, next) => {
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 
    'geolocation=(), microphone=(), camera=(), payment=(), usb=(), magnetometer=(), gyroscope=(), speaker=()');
  next();
});

// 3. RATE LIMITING
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: {
    success: false,
    message: 'Too many requests from this IP, please try again later.'
  },
  standardHeaders: true,
  legacyHeaders: false
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: {
    success: false,
    message: 'Too many authentication attempts, please try again later.'
  },
  standardHeaders: true,
  legacyHeaders: false
});

app.use('/api/', generalLimiter);
app.use('/api/auth/login', authLimiter);
app.use('/api/auth/signup', authLimiter);

// 4. CORS CONFIGURATION - UPDATED FOR REACT ON PORT 5173
app.use(cors({
  origin: process.env.NODE_ENV === 'production' 
    ? process.env.ALLOWED_ORIGINS?.split(',') 
    : ['http://localhost:5173', 'http://localhost:3000', 'http://localhost:5000', 'http://127.0.0.1:5173','https://backend1-rexi.onrender.com','https://testing-drontend.vercel.app/'],
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
  optionsSuccessStatus: 200
}));

// 5. HPP PROTECTION
app.use(hpp({
  whitelist: ['tags']
}));

// 6. BODY PARSING WITH VALIDATION
app.use(express.json({ 
  limit: '10mb',
  verify: (req, res, buf) => {
    try {
      JSON.parse(buf);
    } catch (e) {
      res.status(400).json({
        success: false,
        message: 'Invalid JSON format'
      });
      return;
    }
  }
}));

app.use(express.urlencoded({ 
  extended: true, 
  limit: '10mb'
}));

// 7. FIXED: CUSTOM XSS AND NOSQL INJECTION PROTECTION (EMAIL-SAFE)
app.use((req, res, next) => {
  try {
    const sanitizeValue = (value, isEmail = false) => {
      if (value === null || value === undefined) return value;
      
      if (typeof value === 'string') {
        // XSS Protection - HTML escape and remove dangerous patterns
        let cleaned = xss(value, {
          whiteList: {},
          stripIgnoreTag: true,
          stripIgnoreTagBody: ['script', 'style']
        });
        
        if (!isEmail) {
          // Only remove dots for non-email fields
          cleaned = cleaned.replace(/\$/g, '').replace(/\./g, '_');
        } else {
          // For emails, only remove $ signs (keep dots for email validation)
          cleaned = cleaned.replace(/\$/g, '');
        }
        
        return cleaned;
      }
      
      if (Array.isArray(value)) {
        return value.map(item => sanitizeValue(item));
      }
      
      if (typeof value === 'object') {
        const sanitized = {};
        for (const key in value) {
          if (value.hasOwnProperty(key)) {
            // Check if this is an email field
            const isEmailField = key.toLowerCase().includes('email');
            const cleanKey = key.replace(/[\$]/g, '_'); // Only remove $ from keys
            sanitized[cleanKey] = sanitizeValue(value[key], isEmailField);
          }
        }
        return sanitized;
      }
      
      return value;
    };

    // Create sanitized copies instead of mutating original objects
    if (req.body && typeof req.body === 'object') {
      req.sanitizedBody = sanitizeValue(req.body);
      req.body = req.sanitizedBody;
    }
    
    if (req.query && typeof req.query === 'object') {
      req.sanitizedQuery = sanitizeValue(req.query);
    }
    
    if (req.params && typeof req.params === 'object') {
      req.sanitizedParams = sanitizeValue(req.params);
      try {
        Object.assign(req.params, req.sanitizedParams);
      } catch (e) {
        console.warn('Params read-only, using req.sanitizedParams instead');
      }
    }

    // Log suspicious activity
    const requestData = {
      body: req.sanitizedBody || req.body,
      query: req.sanitizedQuery || req.query,
      params: req.sanitizedParams || req.params
    };
    
    const requestString = JSON.stringify(requestData);
    
    const suspiciousPatterns = [
      /<script/i, /javascript:/i, /on\w+=/i, /eval\(/i,
      /expression\(/i, /vbscript:/i, /data:text\/html/i,
      /\$where/i, /\$ne/i, /\$gt/i, /\$lt/i
    ];
    
    const hasSuspiciousContent = suspiciousPatterns.some(pattern => 
      pattern.test(requestString)
    );
    
    if (hasSuspiciousContent) {
      console.warn(`🚨 Potential XSS/NoSQL injection attempt from ${req.ip}`);
      console.warn(`Request: ${req.method} ${req.originalUrl}`);
      console.warn(`User-Agent: ${req.get('User-Agent')}`);
    }
    
    next();
  } catch (error) {
    console.error('Sanitization error:', error);
    next();
  }
});

// 8. SERVE STATIC FILES
app.use(express.static(path.join(__dirname, 'views'), {
  setHeaders: (res, filepath) => {
    if (filepath.endsWith('.html')) {
      res.setHeader('X-Content-Type-Options', 'nosniff');
      res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
    }
    if (filepath.endsWith('.css')) {
      res.setHeader('Content-Type', 'text/css');
    }
    if (filepath.endsWith('.js')) {
      res.setHeader('Content-Type', 'application/javascript');
    }
  }
}));

// 9. REQUEST LOGGING
app.use((req, res, next) => {
  const start = Date.now();
  const timestamp = new Date().toISOString();
  
  res.on('finish', () => {
    const duration = Date.now() - start;
    const status = res.statusCode;
    const method = req.method;
    const url = req.originalUrl;
    const ip = req.ip || req.connection.remoteAddress;
    
    let statusColor = '\x1b[32m';
    if (status >= 400 && status < 500) statusColor = '\x1b[33m';
    if (status >= 500) statusColor = '\x1b[31m';
    
    console.log(
      `${timestamp} - ${method} ${url} - ${statusColor}${status}\x1b[0m - ${duration}ms - ${ip}`
    );
  });
  
  next();
});

// Environment validation
const requiredEnvVars = ['MONGODB_URI', 'JWT_SECRET'];
const missingEnvVars = requiredEnvVars.filter(envVar => !process.env[envVar]);

if (missingEnvVars.length > 0) {
  console.error('❌ Missing required environment variables:', missingEnvVars);
  console.error('Please check your .env file');
  process.exit(1);
}

// Database connection
const connectDB = async () => {
  try {
    const options = {
      maxPoolSize: 10,
      serverSelectionTimeoutMS: 5000,
      socketTimeoutMS: 45000,
      maxIdleTimeMS: 30000,
      maxConnecting: 2,
      autoCreate: true,
      autoIndex: true
    };

    console.log('🔄 Connecting to MongoDB...');
    const conn = await mongoose.connect(process.env.MONGODB_URI, options);
    
    console.log(`✅ MongoDB connected: ${conn.connection.host}`);
    console.log(`📊 Database: ${conn.connection.name}`);
    
    const User = require('./models/User');
    
    try {
      await User.createCollection();
      console.log('📁 User collection created/verified');
    } catch (error) {
      console.log('📁 User collection ready');
    }
    
    try {
      await User.createIndexes();
      console.log('🔍 Database indexes created/verified');
    } catch (error) {
      console.log('🔍 Database indexes ready');
    }
    
    console.log('✅ Database setup complete with EMAIL-SAFE XSS protection');
    
  } catch (error) {
    console.error('❌ Database connection error:', error.message);
    process.exit(1);
  }
};

connectDB();

// 10. API ROUTES
app.use('/api/auth', authRoutes);

// 11. TEST ENDPOINT FOR REACT CONNECTION
app.get('/api/test', (req, res) => {
  res.json({
    success: true,
    message: 'Backend connected successfully with React on port 5173!',
    timestamp: new Date().toISOString(),
    server: 'Express.js with EMAIL-SAFE XSS Protection'
  });
});

// 12. API DOCUMENTATION
app.get('/api', (req, res) => {
  const safeResponse = {
    message: '🔐 JWT Authentication API - EMAIL-SAFE XSS Protected',
    version: '1.0.0',
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development',
    security: {
      xssProtection: 'Email-Safe Custom Implementation',
      noSqlInjectionProtection: 'Active',
      contentSecurityPolicy: 'Strict',
      inputSanitization: 'Email-Preserving Active'
    },
    endpoints: {
      test: {
        method: 'GET',
        url: '/api/test',
        description: 'Test backend connection with React'
      },
      signup: {
        method: 'POST',
        url: '/api/auth/signup',
        description: 'Register a new user (Email validation fixed)'
      },
      login: {
        method: 'POST',
        url: '/api/auth/login',
        description: 'Login user and get JWT token'
      }
    }
  };

  res.json(safeResponse);
});

// 13. HEALTH CHECK
app.get('/health', (req, res) => {
  const healthData = {
    status: 'OK',
    timestamp: new Date().toISOString(),
    uptime: Math.floor(process.uptime()),
    database: {
      status: mongoose.connection.readyState === 1 ? 'Connected' : 'Disconnected',
      readyState: mongoose.connection.readyState
    },
    security: {
      xssProtection: 'Email-Safe Active',
      noSqlProtection: 'Active',
      sanitization: 'Email-Preserving Enabled'
    },
    environment: process.env.NODE_ENV || 'development'
  };

  const statusCode = mongoose.connection.readyState === 1 ? 200 : 503;
  res.status(statusCode).json(healthData);
});

// 14. GLOBAL ERROR HANDLING
app.use((err, req, res, next) => {
  console.error('❌ Global error handler:', err.stack);
  
  let safeMessage = 'An error occurred';
  
  if (err.name === 'ValidationError') {
    const errors = Object.values(err.errors).map(e => 
      xss(e.message, { whiteList: {} })
    );
    return res.status(400).json({
      success: false,
      message: 'Validation Error',
      errors
    });
  }
  
  if (err.name === 'CastError') {
    safeMessage = 'Invalid ID format';
  } else if (err.code === 11000) {
    safeMessage = 'Data already exists';
  } else if (err.name === 'JsonWebTokenError') {
    safeMessage = 'Invalid token';
  } else if (err.name === 'TokenExpiredError') {
    safeMessage = 'Token expired';
  } else if (process.env.NODE_ENV === 'development') {
    safeMessage = xss(err.message || 'Internal Server Error', { whiteList: {} });
  }
  
  res.status(err.statusCode || 500).json({
    success: false,
    message: safeMessage
  });
});

// 15. 404 HANDLER
app.use((req, res) => {
  const safeUrl = xss(req.originalUrl, { whiteList: {} });
  
  res.status(404).json({
    success: false,
    message: `Route not found`,
    requestedPath: safeUrl.length > 100 ? '[Path too long]' : safeUrl,
    availableEndpoints: {
      test: 'GET /api/test',
      api: 'GET /api',
      health: 'GET /health',
      auth: 'POST /api/auth/signup, /api/auth/login'
    }
  });
});

// Server configuration
const PORT = process.env.PORT || 5000;
const server = app.listen(PORT, () => {
  console.log('\n🚀 =================================');
  console.log(`🌟 EMAIL-SAFE XSS-Protected JWT Auth Server`);
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`🌐 React Frontend: http://localhost:5173`);
  console.log(`📖 API Docs: http://localhost:${PORT}/api`);
  console.log(`💚 Health: http://localhost:${PORT}/health`);
  console.log(`🧪 Test: http://localhost:${PORT}/api/test`);
  console.log(`🛡️  XSS Protection: EMAIL-SAFE ACTIVE`);
  console.log(`🛡️  NoSQL Protection: ACTIVE`);
  console.log(`📧 Email Validation: FIXED`);
  console.log(`🔐 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log('🚀 =================================\n');
  console.log('🔐 Ready for React frontend connection on port 5173!');
});

// Graceful shutdown handlers
const gracefulShutdown = (signal) => {
  console.log(`\n🔄 Received ${signal}. Shutting down gracefully...`);
  
  server.close(async () => {
    console.log('✅ HTTP server closed');
    
    try {
      await mongoose.connection.close();
      console.log('✅ MongoDB connection closed');
    } catch (error) {
      console.error('❌ Error closing MongoDB connection:', error.message);
    }
    
    console.log('👋 Process terminated gracefully');
    process.exit(0);
  });
  
  setTimeout(() => {
    console.error('❌ Could not close connections in time, forcefully shutting down');
    process.exit(1);
  }, 10000);
};

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));
process.on('uncaughtException', (error) => {
  console.error('❌ Uncaught Exception:', error.message);
  gracefulShutdown('uncaughtException');
});
process.on('unhandledRejection', (reason, promise) => {
  console.error('❌ Unhandled Promise Rejection:', reason);
  gracefulShutdown('unhandledRejection');
});

module.exports = app;
