// const mongoose = require('mongoose');
// const bcrypt = require('bcryptjs');
// const validator = require('validator');

// const UserSchema = new mongoose.Schema({
//   username: {
//     type: String,
//     required: [true, 'Please provide username'],
//     unique: true,
//     trim: true,
//     minlength: [3, 'Username must be at least 3 characters'],
//     maxlength: [50, 'Username cannot exceed 50 characters'],
//     match: [/^[a-zA-Z0-9_-]+$/, 'Username can only contain letters, numbers, underscores, and hyphens']
//   },
//   email: {
//     type: String,
//     required: [true, 'Please provide email'],
//     unique: true,
//     lowercase: true,
//     validate: {
//       validator: validator.isEmail,
//       message: 'Please provide a valid email address'
//     }
//   },
//   password: {
//     type: String,
//     required: [true, 'Please provide password'],
//     minlength: [6, 'Password must be at least 6 characters'],
//     select: false  // ✅ This is correct - keeps password hidden by default
//   },
//   role: {
//     type: String,
//     enum: ['user', 'admin'],
//     default: 'user'
//   },
//   isActive: {
//     type: Boolean,
//     default: true
//   },
//   lastLogin: {
//     type: Date
//   },
//   lastLoginIP: {
//     type: String
//   },
//   createdAt: {
//     type: Date,
//     default: Date.now
//   }
// });

// // ✅ SECURITY: Add compound index to prevent timing attacks
// UserSchema.index({ email: 1, username: 1 });

// // Hash password before saving
// UserSchema.pre('save', async function(next) {
//   if (!this.isModified('password')) {
//     return next();
//   }
  
//   try {
//     const salt = await bcrypt.genSalt(12);  // ✅ SECURITY: Salt rounds = 12 (good)
//     this.password = await bcrypt.hash(this.password, salt);
//     next();
//   } catch (error) {
//     next(error);  // ✅ ADDED: Proper error handling
//   }
// });

// // Compare password method
// UserSchema.methods.comparePassword = async function(candidatePassword) {
//   try {
//     return await bcrypt.compare(candidatePassword, this.password);
//   } catch (error) {
//     return false;  // ✅ ADDED: Return false on error instead of throwing
//   }
// };

// // ✅ ADDED: Method to check if user account is active (security enhancement)
// UserSchema.methods.isAccountActive = function() {
//   return this.isActive;
// };

// // ✅ ADDED: Static method to find user safely (prevents timing attacks)
// UserSchema.statics.findByEmailOrUsername = async function(identifier) {
//   try {
//     const user = await this.findOne({
//       $or: [
//         { email: identifier.toLowerCase() },
//         { username: identifier }
//       ],
//       isActive: true  // Only return active users
//     }).select('+password');  // Include password for authentication
    
//     return user;
//   } catch (error) {
//     return null;
//   }
// };

// module.exports = mongoose.model('User', UserSchema);



const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const validator = require('validator');

const UserSchema = new mongoose.Schema({
  username: {
    type: String,
    required: [true, 'Please provide username'],
    unique: true,
    trim: true,
    minlength: [3, 'Username must be at least 3 characters'],
    maxlength: [50, 'Username cannot exceed 50 characters'],
    match: [/^[a-zA-Z0-9_-]+$/, 'Username can only contain letters, numbers, underscores, and hyphens']
  },
  email: {
    type: String,
    required: [true, 'Please provide email'],
    unique: true,
    lowercase: true,
    validate: {
      validator: validator.isEmail,
      message: 'Please provide a valid email address'
    }
  },
  password: {
    type: String,
    required: [true, 'Please provide password'],
    minlength: [6, 'Password must be at least 6 characters'],
    select: false
  },
  role: {
    type: String,
    enum: ['user', 'admin'],
    default: 'user'
  },
  isActive: {
    type: Boolean,
    default: true
  },
  lastLogin: {
    type: Date
  },
  lastLoginIP: {
    type: String
  },
  tokenVersion: {
    type: Number,
    default: 0
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

UserSchema.index({ email: 1, username: 1 });

UserSchema.pre('save', async function(next) {
  if (!this.isModified('password')) {
    return next();
  }

  try {
    const salt = await bcrypt.genSalt(12);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (error) {
    next(error);
  }
});

UserSchema.methods.comparePassword = async function(candidatePassword) {
  try {
    return await bcrypt.compare(candidatePassword, this.password);
  } catch (error) {
    return false;
  }
};

UserSchema.methods.isAccountActive = function() {
  return this.isActive;
};

UserSchema.statics.findByEmailOrUsername = async function(identifier) {
  try {
    const user = await this.findOne({
      $or: [
        { email: identifier.toLowerCase() },
        { username: identifier }
      ],
      isActive: true
    }).select('+password');

    return user;
  } catch (error) {
    return null;
  }
};

module.exports = mongoose.model('User', UserSchema);
