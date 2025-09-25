// const express = require('express');
// const rateLimit = require('express-rate-limit');
// const validator = require('validator');
// const User = require('../models/User');
// const { auth, adminAuth, generateTokens } = require('../middleware/auth');

// const router = express.Router();

// // Strict rate limiting for auth endpoints
// const authLimiter = rateLimit({
//   windowMs: 15 * 60 * 1000,
//   max: 5,
//   message: {
//     success: false,
//     message: 'Too many authentication attempts. Please try again later.'
//   },
//   standardHeaders: true,
//   legacyHeaders: false
// });

// // Enhanced signup with proper email validation
// router.post('/signup', authLimiter, async (req, res) => {
//   try {
//     const { username, email, password, confirmPassword } = req.body;

//     // Enhanced validation
//     if (!username || !email || !password) {
//       return res.status(400).json({
//         success: false,
//         message: 'Username, email, and password are required'
//       });
//     }

//     // Email validation using validator.js
//     if (!validator.isEmail(email)) {
//       return res.status(400).json({
//         success: false,
//         message: 'Please provide a valid email address'
//       });
//     }

//     // Additional email checks
//     if (email.length > 254) {
//       return res.status(400).json({
//         success: false,
//         message: 'Email address is too long'
//       });
//     }

//     if (password !== confirmPassword) {
//       return res.status(400).json({
//         success: false,
//         message: 'Passwords do not match'
//       });
//     }

//     // Password strength validation
//     if (password.length < 6) {
//       return res.status(400).json({
//         success: false,
//         message: 'Password must be at least 6 characters long'
//       });
//     }

//     // Check if user exists
//     const existingUser = await User.findOne({
//       $or: [{ email: email.toLowerCase() }, { username }]
//     });

//     if (existingUser) {
//       return res.status(409).json({
//         success: false,
//         message: 'User with this email or username already exists'
//       });
//     }

//     // Create user
//     const user = await User.create({
//       username,
//       email: email.toLowerCase(),
//       password,
//       lastLoginIP: req.ip
//     });

//     // Generate tokens
//     const { accessToken, refreshToken } = generateTokens(user, req);

//     // ✅ ONLY CHANGE: Modified response format to match React expectations
//     res.status(201).json({
//       success: true,
//       message: 'User registered successfully',
//       token: accessToken,        // ← React expects 'token' (not 'tokens.accessToken')
//       refreshToken,              // ← Keep refresh token separate
//       user: {
//         id: user._id,
//         username: user.username,
//         email: user.email,
//         role: user.role,
//         createdAt: user.createdAt
//       }
//     });

//   } catch (error) {
//     console.error('Signup error:', error);
    
//     if (error.code === 11000) {
//       return res.status(409).json({
//         success: false,
//         message: 'User with this email or username already exists'
//       });
//     }

//     if (error.name === 'ValidationError') {
//       const errors = Object.values(error.errors).map(err => err.message);
//       return res.status(400).json({
//         success: false,
//         message: 'Validation failed',
//         errors
//       });
//     }

//     res.status(500).json({
//       success: false,
//       message: 'Internal server error during registration'
//     });
//   }
// });

// // Enhanced login
// router.post('/login', authLimiter, async (req, res) => {
//   try {
//     const { email, password } = req.body;

//     if (!email || !password) {
//       return res.status(400).json({
//         success: false,
//         message: 'Email and password are required'
//       });
//     }

//     // Validate email format
//     if (!validator.isEmail(email)) {
//       return res.status(400).json({
//         success: false,
//         message: 'Please provide a valid email address'
//       });
//     }

//     // Find user and include password
//     const user = await User.findOne({ email: email.toLowerCase() }).select('+password');

//     if (!user || !(await user.comparePassword(password))) {
//       return res.status(401).json({
//         success: false,
//         message: 'Invalid credentials'
//       });
//     }

//     // Generate tokens
//     const { accessToken, refreshToken } = generateTokens(user, req);

//     // Update login information
//     user.lastLogin = new Date();
//     user.lastLoginIP = req.ip;
//     await user.save();

//     // ✅ ONLY CHANGE: Modified response format to match React expectations
//     res.status(200).json({
//       success: true,
//       message: 'Login successful',
//       token: accessToken,        // ← React expects 'token' (not 'tokens.accessToken')
//       refreshToken,              // ← Keep refresh token separate
//       user: {
//         id: user._id,
//         username: user.username,
//         email: user.email,
//         role: user.role,
//         lastLogin: user.lastLogin,
//         createdAt: user.createdAt
//       }
//     });

//   } catch (error) {
//     console.error('Login error:', error);
//     res.status(500).json({
//       success: false,
//       message: 'Internal server error during login'
//     });
//   }
// });

// // Get current user
// router.get('/me', auth, async (req, res) => {
//   try {
//     res.status(200).json({
//       success: true,
//       user: {
//         id: req.user._id,
//         username: req.user.username,
//         email: req.user.email,
//         role: req.user.role,
//         lastLogin: req.user.lastLogin,
//         createdAt: req.user.createdAt
//       }
//     });
//   } catch (error) {
//     console.error('Get profile error:', error);
//     res.status(500).json({
//       success: false,
//       message: 'Server error'
//     });
//   }
// });

// // Update profile
// router.put('/profile', auth, async (req, res) => {
//   try {
//     const { username } = req.body;
    
//     const updatedUser = await User.findByIdAndUpdate(
//       req.user._id,
//       { username },
//       { new: true, runValidators: true }
//     );

//     res.status(200).json({
//       success: true,
//       message: 'Profile updated successfully',
//       user: {
//         id: updatedUser._id,
//         username: updatedUser.username,
//         email: updatedUser.email,
//         role: updatedUser.role,
//         createdAt: updatedUser.createdAt
//       }
//     });
//   } catch (error) {
//     console.error('Update profile error:', error);
//     res.status(500).json({
//       success: false,
//       message: 'Server error'
//     });
//   }
// });

// // Get all users (Admin only)
// router.get('/users', auth, adminAuth, async (req, res) => {
//   try {
//     const users = await User.find({}).select('-password');
    
//     res.status(200).json({
//       success: true,
//       count: users.length,
//       users
//     });
//   } catch (error) {
//     console.error('Get users error:', error);
//     res.status(500).json({
//       success: false,
//       message: 'Server error'
//     });
//   }
// });

// // Delete user (Admin only)
// router.delete('/users/:id', auth, adminAuth, async (req, res) => {
//   try {
//     const user = await User.findByIdAndDelete(req.params.id);
    
//     if (!user) {
//       return res.status(404).json({
//         success: false,
//         message: 'User not found'
//       });
//     }

//     res.status(200).json({
//       success: true,
//       message: 'User deleted successfully'
//     });
//   } catch (error) {
//     console.error('Delete user error:', error);
//     res.status(500).json({
//       success: false,
//       message: 'Server error'
//     });
//   }
// });

// // Logout
// router.post('/logout', auth, (req, res) => {
//   res.status(200).json({
//     success: true,
//     message: 'Logged out successfully'
//   });
// });

// module.exports = router;



const express = require('express');
const rateLimit = require('express-rate-limit');
const validator = require('validator');
const User = require('../models/User');
const RefreshToken = require('../models/RefreshToken');
const { auth, adminAuth, generateTokens, storeRefreshToken, validateRefreshToken } = require('../middleware/auth');

const router = express.Router();

// Strict rate limiting for auth endpoints
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: {
    success: false,
    message: 'Too many authentication attempts. Please try again later.'
  },
  standardHeaders: true,
  legacyHeaders: false
});

// Enhanced signup with proper email validation
router.post('/signup', authLimiter, async (req, res) => {
  try {
    const { username, email, password, confirmPassword } = req.body;

    // Enhanced validation
    if (!username || !email || !password) {
      return res.status(400).json({
        success: false,
        message: 'Username, email, and password are required'
      });
    }

    // Email validation using validator.js
    if (!validator.isEmail(email)) {
      return res.status(400).json({
        success: false,
        message: 'Please provide a valid email address'
      });
    }

    // Additional email checks
    if (email.length > 254) {
      return res.status(400).json({
        success: false,
        message: 'Email address is too long'
      });
    }

    if (password !== confirmPassword) {
      return res.status(400).json({
        success: false,
        message: 'Passwords do not match'
      });
    }

    // Password strength validation
    if (password.length < 6) {
      return res.status(400).json({
        success: false,
        message: 'Password must be at least 6 characters long'
      });
    }

    // Check if user exists
    const existingUser = await User.findOne({
      $or: [{ email: email.toLowerCase() }, { username }]
    });

    if (existingUser) {
      return res.status(409).json({
        success: false,
        message: 'User with this email or username already exists'
      });
    }

    // Create user
    const user = await User.create({
      username,
      email: email.toLowerCase(),
      password,
      lastLoginIP: req.ip
    });

    // Generate tokens
    const { accessToken, refreshToken } = generateTokens(user, req);
    
    // Store refresh token
    await storeRefreshToken(user._id, refreshToken, req);

    res.status(201).json({
      success: true,
      message: 'User registered successfully',
      token: accessToken,
      refreshToken,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role,
        createdAt: user.createdAt
      }
    });

  } catch (error) {
    console.error('Signup error:', error);

    if (error.code === 11000) {
      return res.status(409).json({
        success: false,
        message: 'User with this email or username already exists'
      });
    }

    if (error.name === 'ValidationError') {
      const errors = Object.values(error.errors).map(err => err.message);
      return res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors
      });
    }

    res.status(500).json({
      success: false,
      message: 'Internal server error during registration'
    });
  }
});

// Enhanced login
router.post('/login', authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: 'Email and password are required'
      });
    }

    // Validate email format
    if (!validator.isEmail(email)) {
      return res.status(400).json({
        success: false,
        message: 'Please provide a valid email address'
      });
    }

    // Find user and include password
    const user = await User.findOne({ email: email.toLowerCase() }).select('+password');

    if (!user || !(await user.comparePassword(password))) {
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials'
      });
    }

    // Generate tokens
    const { accessToken, refreshToken } = generateTokens(user, req);
    
    // Store refresh token
    await storeRefreshToken(user._id, refreshToken, req);

    // Update login information
    user.lastLogin = new Date();
    user.lastLoginIP = req.ip;
    await user.save();

    res.status(200).json({
      success: true,
      message: 'Login successful',
      token: accessToken,
      refreshToken,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role,
        lastLogin: user.lastLogin,
        createdAt: user.createdAt
      }
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error during login'
    });
  }
});

// Token refresh endpoint
router.post('/refresh', async (req, res) => {
  try {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      return res.status(401).json({
        success: false,
        message: 'Refresh token required'
      });
    }

    // Validate refresh token
    const { tokenDoc } = await validateRefreshToken(refreshToken);
    
    // Generate new access token
    const { accessToken: newAccessToken } = generateTokens(tokenDoc.userId, req);

    res.json({
      success: true,
      token: newAccessToken,
      message: 'Token refreshed successfully'
    });

  } catch (error) {
    console.error('Token refresh error:', error);
    res.status(401).json({
      success: false,
      message: 'Invalid or expired refresh token'
    });
  }
});

// Enhanced logout (revokes refresh token)
router.post('/logout-enhanced', auth, async (req, res) => {
  try {
    const { refreshToken } = req.body;
    
    if (refreshToken) {
      await RefreshToken.updateOne(
        { token: refreshToken, userId: req.user._id },
        { isActive: false }
      );
    }

    res.json({
      success: true,
      message: 'Logged out successfully'
    });

  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({
      success: false,
      message: 'Logout failed'
    });
  }
});

// Token configuration info endpoint
router.get('/token-info', (req, res) => {
  res.json({
    success: true,
    tokenConfig: {
      accessTokenExpires: process.env.ACCESS_TOKEN_EXPIRES || '15m',
      refreshTokenExpires: process.env.REFRESH_TOKEN_EXPIRES || '7d',
      refreshTokenExpireDays: process.env.JWT_REFRESH_EXPIRE_DAYS || '7',
      issuer: process.env.JWT_ISSUER || 'jwt-auth-api',
      audience: process.env.JWT_AUDIENCE || 'jwt-auth-users'
    },
    environment: process.env.NODE_ENV || 'development'
  });
});

// Get current user
router.get('/me', auth, async (req, res) => {
  try {
    res.status(200).json({
      success: true,
      user: {
        id: req.user._id,
        username: req.user.username,
        email: req.user.email,
        role: req.user.role,
        lastLogin: req.user.lastLogin,
        createdAt: req.user.createdAt
      }
    });
  } catch (error) {
    console.error('Get profile error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

// Update profile
router.put('/profile', auth, async (req, res) => {
  try {
    const { username } = req.body;

    const updatedUser = await User.findByIdAndUpdate(
      req.user._id,
      { username },
      { new: true, runValidators: true }
    );

    res.status(200).json({
      success: true,
      message: 'Profile updated successfully',
      user: {
        id: updatedUser._id,
        username: updatedUser.username,
        email: updatedUser.email,
        role: updatedUser.role,
        createdAt: updatedUser.createdAt
      }
    });
  } catch (error) {
    console.error('Update profile error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

// Get all users (Admin only)
router.get('/users', auth, adminAuth, async (req, res) => {
  try {
    const users = await User.find({}).select('-password');
    res.status(200).json({
      success: true,
      count: users.length,
      users
    });
  } catch (error) {
    console.error('Get users error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

// Delete user (Admin only)
router.delete('/users/:id', auth, adminAuth, async (req, res) => {
  try {
    const user = await User.findByIdAndDelete(req.params.id);

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    res.status(200).json({
      success: true,
      message: 'User deleted successfully'
    });
  } catch (error) {
    console.error('Delete user error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

// Original logout (unchanged for backward compatibility)
router.post('/logout', auth, (req, res) => {
  res.status(200).json({
    success: true,
    message: 'Logged out successfully'
  });
});

module.exports = router;
