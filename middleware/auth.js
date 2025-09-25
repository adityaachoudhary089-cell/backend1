// const jwt = require('jsonwebtoken');
// const User = require('../models/User');

// // Generate JWT tokens
// const generateTokens = (user, req) => {
//   const payload = {
//     id: user._id,
//     username: user.username,
//     email: user.email,
//     role: user.role
//   };

//   const accessToken = jwt.sign(payload, process.env.JWT_SECRET, {
//     expiresIn: '15m',
//     issuer: process.env.JWT_ISSUER || 'jwt-auth-api',
//     audience: process.env.JWT_AUDIENCE || 'jwt-auth-users'
//   });

//   const refreshToken = jwt.sign(
//     { id: user._id, type: 'refresh' },
//     process.env.JWT_REFRESH_SECRET || process.env.JWT_SECRET,
//     {
//       expiresIn: '7d',
//       issuer: process.env.JWT_ISSUER || 'jwt-auth-api',
//       audience: process.env.JWT_AUDIENCE || 'jwt-auth-users'
//     }
//   );

//   return { accessToken, refreshToken };
// };

// // Authentication middleware
// const auth = async (req, res, next) => {
//   try {
//     let token = req.header('Authorization');
    
//     if (!token) {
//       return res.status(401).json({
//         success: false,
//         message: 'No token provided, access denied'
//       });
//     }

//     if (token.startsWith('Bearer ')) {
//       token = token.slice(7);
//     }

//     const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
//     const user = await User.findById(decoded.id);
//     if (!user || !user.isActive) {
//       return res.status(401).json({
//         success: false,
//         message: 'Token is not valid - user not found or inactive'
//       });
//     }

//     req.token = token;
//     req.user = user;
//     next();
    
//   } catch (error) {
//     console.error('Auth middleware error:', error.message);
    
//     if (error.name === 'JsonWebTokenError') {
//       return res.status(401).json({
//         success: false,
//         message: 'Invalid token format'
//       });
//     }
    
//     if (error.name === 'TokenExpiredError') {
//       return res.status(401).json({
//         success: false,
//         message: 'Token has expired'
//       });
//     }
    
//     res.status(401).json({
//       success: false,
//       message: 'Token verification failed'
//     });
//   }
// };

// // Admin middleware
// const adminAuth = (req, res, next) => {
//   try {
//     if (!req.user) {
//       return res.status(401).json({
//         success: false,
//         message: 'Authentication required'
//       });
//     }

//     if (req.user.role !== 'admin') {
//       console.warn(`Unauthorized admin access attempt by user: ${req.user.email} from IP: ${req.ip}`);
      
//       return res.status(403).json({
//         success: false,
//         message: 'Admin privileges required'
//       });
//     }

//     console.log(`Admin action: ${req.method} ${req.originalUrl} by ${req.user.email} from IP: ${req.ip}`);
//     next();
    
//   } catch (error) {
//     console.error('Admin auth error:', error);
//     res.status(500).json({
//       success: false,
//       message: 'Authorization check failed'
//     });
//   }
// };

// module.exports = { auth, adminAuth, generateTokens };




const jwt = require('jsonwebtoken');
const User = require('../models/User');
const RefreshToken = require('../models/RefreshToken');

// Enhanced generateTokens function with configurable expiration
const generateTokens = (user, req) => {
  const payload = {
    id: user._id,
    username: user.username,
    email: user.email,
    role: user.role,
    tokenVersion: user.tokenVersion || 0
  };

  const accessToken = jwt.sign(payload, process.env.JWT_SECRET, {
    expiresIn: process.env.ACCESS_TOKEN_EXPIRES || '15m',
    issuer: process.env.JWT_ISSUER || 'jwt-auth-api',
    audience: process.env.JWT_AUDIENCE || 'jwt-auth-users'
  });

  const refreshToken = jwt.sign(
    { 
      id: user._id, 
      type: 'refresh',
      tokenVersion: user.tokenVersion || 0
    },
    process.env.JWT_REFRESH_SECRET || process.env.JWT_SECRET,
    {
      expiresIn: process.env.REFRESH_TOKEN_EXPIRES || '7d',
      issuer: process.env.JWT_ISSUER || 'jwt-auth-api',
      audience: process.env.JWT_AUDIENCE || 'jwt-auth-users'
    }
  );

  return { accessToken, refreshToken };
};

// Store refresh token in database
const storeRefreshToken = async (userId, refreshToken, req) => {
  try {
    const deviceInfo = {
      userAgent: req.get('User-Agent'),
      ipAddress: req.ip
    };

    const tokenDoc = new RefreshToken({
      token: refreshToken,
      userId,
      deviceInfo
    });

    await tokenDoc.save();
    return tokenDoc;
  } catch (error) {
    console.error('Failed to store refresh token:', error);
    throw error;
  }
};

// Validate refresh token
const validateRefreshToken = async (token) => {
  try {
    const decoded = jwt.verify(token, process.env.JWT_REFRESH_SECRET || process.env.JWT_SECRET);
    
    const tokenDoc = await RefreshToken.findOne({ 
      token, 
      isActive: true,
      userId: decoded.id
    }).populate('userId');

    if (!tokenDoc || tokenDoc.expiresAt < new Date()) {
      throw new Error('Invalid or expired refresh token');
    }

    return { tokenDoc, decoded };
  } catch (error) {
    throw new Error('Invalid refresh token');
  }
};

// Authentication middleware
const auth = async (req, res, next) => {
  try {
    let token = req.header('Authorization');

    if (!token) {
      return res.status(401).json({
        success: false,
        message: 'No token provided, access denied'
      });
    }

    if (token.startsWith('Bearer ')) {
      token = token.slice(7);
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.id);

    if (!user || !user.isActive) {
      return res.status(401).json({
        success: false,
        message: 'Token is not valid - user not found or inactive'
      });
    }

    req.token = token;
    req.user = user;
    next();
  } catch (error) {
    console.error('Auth middleware error:', error.message);
    
    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({
        success: false,
        message: 'Invalid token format'
      });
    }

    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({
        success: false,
        message: 'Token has expired',
        code: 'TOKEN_EXPIRED'
      });
    }

    res.status(401).json({
      success: false,
      message: 'Token verification failed'
    });
  }
};

// Admin middleware
const adminAuth = (req, res, next) => {
  try {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        message: 'Authentication required'
      });
    }

    if (req.user.role !== 'admin') {
      console.warn(`Unauthorized admin access attempt by user: ${req.user.email} from IP: ${req.ip}`);
      return res.status(403).json({
        success: false,
        message: 'Admin privileges required'
      });
    }

    console.log(`Admin action: ${req.method} ${req.originalUrl} by ${req.user.email} from IP: ${req.ip}`);
    next();
  } catch (error) {
    console.error('Admin auth error:', error);
    res.status(500).json({
      success: false,
      message: 'Authorization check failed'
    });
  }
};

module.exports = { 
  auth, 
  adminAuth, 
  generateTokens, 
  storeRefreshToken, 
  validateRefreshToken 
};
