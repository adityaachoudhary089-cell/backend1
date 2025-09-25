const mongoose = require('mongoose');

const refreshTokenSchema = new mongoose.Schema({
  token: {
    type: String,
    required: true,
    unique: true
  },
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  expiresAt: {
    type: Date,
    required: true,
    default: function() {
      const days = process.env.JWT_REFRESH_EXPIRE_DAYS || 7;
      return new Date(Date.now() + (days * 24 * 60 * 60 * 1000));
    },
    expires: 0 // MongoDB auto-delete when expired
  },
  isActive: {
    type: Boolean,
    default: true
  },
  deviceInfo: {
    userAgent: String,
    ipAddress: String
  }
}, {
  timestamps: true
});

module.exports = mongoose.model('RefreshToken', refreshTokenSchema);
