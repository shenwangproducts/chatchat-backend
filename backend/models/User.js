const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    trim: true,
    index: true
  },
  email: {
    type: String, 
    required: true, 
    unique: true, 
    trim: true, 
    lowercase: true,
    index: true 
  },
  emailVerified: { type: Boolean, default: false },
  emailVerificationToken: { type: String, sparse: true },
  emailVerificationTokenExpiry: { type: Date, sparse: true },
  phone: {
    type: String,
    trim: true,
    sparse: true
  },
  passwordHash: { type: String, required: true },
  passwordSalt: { type: String, required: true },
  authToken: String,
  tokenExpiry: Date,
  userType: { type: String, default: 'user' },
  settings: {
    language: { type: String, default: 'en' },
    theme: { type: String, default: 'white' }
  },
  userId: { type: String, unique: true, sparse: true },
  lastUserIdChange: Date,
  lastUsernameChange: Date,
  profilePicture: String,
  coverImage: String,
  bio: String,
  aboutMe: String,
  jobTitle: String,
  hometown: String,
  currentAddress: String,
  birthDate: Date,
  relationshipStatus: String,
  workplace: String,
  workStartDate: Date,
  workCountry: String,
  education: mongoose.Schema.Types.Mixed,
  interests: [String],
  socials: {
    facebook: String, instagram: String, line: String, tiktok: String, twitter: String
  },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
  lastLogin: Date,
  failedLoginAttempts: { type: Number, default: 0 },
  isActive: { type: Boolean, default: true },
  pdpaConsent: { type: Boolean, default: false },
  consentTimestamp: Date,
  fcmToken: { type: String }, // สำหรับ Push Notifications
  activePackage: {
    name: String,
    purchasedAt: Date,
    expiresAt: Date
  },
  frameType: { type: String, default: 'none' },
  badgeUrl: { type: String, default: '' },
  notificationSettings: {
    chatNotifications: { type: Boolean, default: true },
    friendRequestNotifications: { type: Boolean, default: true },
    systemNotifications: { type: Boolean, default: true },
    soundEnabled: { type: Boolean, default: true },
    vibrationEnabled: { type: Boolean, default: true }
  },
  blockedUsers: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }]
});

userSchema.index({ email: 1 });
userSchema.index({ userId: 1 });
userSchema.index({ createdAt: -1 });
userSchema.index({ phone: 1 });

module.exports = mongoose.model('User', userSchema);