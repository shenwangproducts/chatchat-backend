const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
require('dotenv').config();

const admin = require('firebase-admin');

const app = express();
const PORT = process.env.PORT || 30001;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';

// ✅ Trust Proxy (Required for Render/Heroku behind load balancer)
app.set('trust proxy', 1);

// Firebase initialization
if (process.env.FIREBASE_SERVICE_ACCOUNT_KEY) {
  try {
    const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_KEY);
    admin.initializeApp({
      credential: admin.credential.cert(serviceAccount)
    });
    console.log('✅ Firebase initialized successfully');
  } catch (error) {
    console.error('❌ Failed to initialize Firebase:', error.message);
  }
} else {
  console.warn('⚠️ FIREBASE_SERVICE_ACCOUNT_KEY not set, push notifications disabled');
}

// ✅ Security Middleware
app.use(helmet({
  crossOriginResourcePolicy: { policy: "cross-origin" }
}));

// ✅ Rate Limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  limit: 100, // limit each IP to 100 requests per windowMs
  handler: (req, res, next, options) => {
    res.status(options.statusCode).json({
      success: false,
      error: 'Too many requests from this IP, please try again later.'
    });
  }
});
app.use('/api/', limiter);

// Middleware
app.use(cors({
  origin: true, // Reflect request origin to allow credentials safely
  credentials: true
}));
app.use(express.json({ limit: '10mb' }));
// Serve uploaded files
app.use('/uploads', express.static('uploads'));
app.use('/uploads/media', express.static('uploads/media'));

// ✅ Configure Multer for file uploads
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    const uploadDir = 'uploads/';
    if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);
    cb(null, uploadDir);
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + '-' + Math.round(Math.random() * 1E9) + path.extname(file.originalname));
  }
});

const fileFilter = (req, file, cb) => {
  const allowedTypes = /jpeg|jpg|png|gif|pdf|doc|docx|xls|xlsx|mp4|mov|mp3|wav/;
  const mimetype = allowedTypes.test(file.mimetype);
  const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());

  if (mimetype && extname) {
    return cb(null, true);
  }
  cb(new Error('File type not allowed: ' + file.mimetype));
};

const upload = multer({ 
  storage: storage,
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB limit
  fileFilter: fileFilter
});

// ✅ Configure Multer for media uploads (videos, photos) - Higher file size limit
const mediaStorage = multer.diskStorage({
  destination: function (req, file, cb) {
    const uploadDir = 'uploads/media/';
    if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });
    cb(null, uploadDir);
  },
  filename: function (req, file, cb) {
    const uploadId = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, uploadId + path.extname(file.originalname));
  }
});

const mediaFilter = (req, file, cb) => {
  // Comprehensive MIME type validation
  const allowedMimeTypes = [
    'image/jpeg',
    'image/jpg',
    'image/png',
    'image/gif',
    'video/mp4',
    'video/quicktime', // .mov files
    'video/webm',
    'video/x-msvideo', // .avi
    'video/x-matroska', // .mkv
    'video/x-flv', // .flv
    'video/x-ms-wmv' // .wmv
  ];

  // Allowed file extensions
  const allowedExtensions = ['jpeg', 'jpg', 'png', 'gif', 'mp4', 'mov', 'webm', 'avi', 'mkv', 'flv', 'wmv'];
  const fileExtension = path.extname(file.originalname).toLowerCase().slice(1);

  const mimeTypeAllowed = allowedMimeTypes.includes(file.mimetype);
  const extensionAllowed = allowedExtensions.includes(fileExtension);

  console.log('🔍 File validation:', {
    originalName: file.originalname,
    mimeType: file.mimetype,
    extension: fileExtension,
    mimeTypeAllowed,
    extensionAllowed
  });

  // Allow specific mime types OR generic binary if extension is valid
  if ((mimeTypeAllowed || file.mimetype === 'application/octet-stream') && extensionAllowed) {
    return cb(null, true);
  }
  
  const error = `Media type not allowed - MIME: ${file.mimetype}, Extension: ${fileExtension}`;
  console.error('❌ ' + error);
  cb(new Error(error));
};

const mediaUpload = multer({ 
  storage: mediaStorage,
  limits: { fileSize: 500 * 1024 * 1024 }, // 500MB limit for media
  fileFilter: mediaFilter
});

// ✅ MongoDB Connection
const mongoURI = process.env.MONGODB_URI;
if (!mongoURI) {
  console.error('❌ MONGODB_URI is not defined in environment variables');
  process.exit(1);
}

mongoose.connect(mongoURI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
});

const db = mongoose.connection;
db.on('error', console.error.bind(console, 'MongoDB connection error:'));
db.once('open', () => {
  console.log('✅ Connected to MongoDB successfully');
  createSystemAccount();
  createAdminUser();
});

// =============================================
// 🗃️ DATABASE SCHEMAS
// =============================================
// User Schema
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
  profilePicture: String,
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
  lastLogin: Date,
  failedLoginAttempts: { type: Number, default: 0 },
  isActive: { type: Boolean, default: true },
  pdpaConsent: { type: Boolean, default: false },
  consentTimestamp: Date,
  fcmToken: { type: String }, // สำหรับ Push Notifications
  notificationSettings: {
    chatNotifications: { type: Boolean, default: true },
    friendRequestNotifications: { type: Boolean, default: true },
    systemNotifications: { type: Boolean, default: true },
    soundEnabled: { type: Boolean, default: true },
    vibrationEnabled: { type: Boolean, default: true }
  }
});

userSchema.index({ email: 1 });
userSchema.index({ userId: 1 });
userSchema.index({ createdAt: -1 });
userSchema.index({ phone: 1 });

const User = mongoose.model('User', userSchema);

// Wallet Schema
const walletSchema = new mongoose.Schema({
  userId: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: true,
    unique: true
  },
  balance: { type: Number, default: 0.0 },
  coinPoints: { type: Number, default: 0 },
  currency: { type: String, default: 'THB' },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

walletSchema.index({ userId: 1 });

const Wallet = mongoose.model('Wallet', walletSchema);

// Transaction Schema
const transactionSchema = new mongoose.Schema({
  userId: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: true 
  },
  walletId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Wallet',
    required: true
  },
  type: { 
    type: String, 
    enum: ['topup', 'transfer', 'payment', 'withdraw', 'reward', 'exchange'],
    required: true 
  },
  amount: { type: Number, required: true },
  currency: { type: String, default: 'THB' },
  description: { type: String, required: true },
  status: { 
    type: String, 
    enum: ['pending', 'completed', 'failed', 'cancelled'],
    default: 'pending'
  },
  referenceId: { type: String, unique: true },
  metadata: { type: Map, of: mongoose.Schema.Types.Mixed },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

transactionSchema.index({ userId: 1, createdAt: -1 });
transactionSchema.index({ referenceId: 1 });

const Transaction = mongoose.model('Transaction', transactionSchema);

// Identity Verification Schema - IMPROVED VERSION
const identityVerificationSchema = new mongoose.Schema({
  userId: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: true,
    index: true
  },
  verificationMethod: { 
    type: String, 
    enum: ['id_card', 'passport'],
    required: true 
  },
  status: { 
    type: String, 
    enum: ['pending', 'verified', 'rejected', 'expired'],
    default: 'pending',
    index: true
  },
  documentNumber: { 
    type: String, 
    required: true,
    trim: true
  },
  fullName: { 
    type: String, 
    required: true,
    trim: true
  },
  birthDate: { 
    type: Date 
  },
  nationality: { 
    type: String,
    trim: true
  },
  expiryDate: { 
    type: Date 
  },
  faceScanData: {
    stepsCompleted: { type: Number, default: 0 },
    totalSteps: { type: Number, default: 6 },
    scanResults: [{
      step: { type: Number, required: true },
      title: { type: String, required: true },
      status: { 
        type: String, 
        enum: ['pending', 'completed', 'failed'],
        default: 'pending'
      },
      timestamp: { type: Date, default: Date.now }
    }],
    completedAt: Date
  },
  verifiedAt: { type: Date },
  rejectedAt: { type: Date },
  rejectionReason: { type: String },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

// ✅ เพิ่ม compound index เพื่อป้องกันการยืนยันซ้ำ
identityVerificationSchema.index({ userId: 1, status: 1 });

const IdentityVerification = mongoose.model('IdentityVerification', identityVerificationSchema);

// Reward Points Schema
const rewardSchema = new mongoose.Schema({
  userId: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: true 
  },
  type: { 
    type: String, 
    enum: ['earn', 'redeem', 'expire'],
    required: true 
  },
  points: { type: Number, required: true },
  description: { type: String, required: true },
  balanceAfter: { type: Number, required: true },
  referenceId: { type: String },
  metadata: { type: Map, of: mongoose.Schema.Types.Mixed },
  createdAt: { type: Date, default: Date.now }
});

rewardSchema.index({ userId: 1, createdAt: -1 });

const Reward = mongoose.model('Reward', rewardSchema);

// Bank Service Schema
const bankServiceSchema = new mongoose.Schema({
  code: { type: String, required: true, unique: true },
  name: { type: String, required: true },
  nameEn: { type: String, required: true },
  nameZh: { type: String, required: true },
  color: { type: String, default: '#000000' },
  icon: { type: String, default: 'account_balance' },
  deeplink: {
    scan_pay: String,
    transfer: String,
    topup: String,
    withdraw: String
  },
  packageName: String,
  isActive: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

bankServiceSchema.index({ code: 1 });
bankServiceSchema.index({ isActive: 1 });

const BankService = mongoose.model('BankService', bankServiceSchema);

// Chat Schema
const chatSchema = new mongoose.Schema({
  participants: [{ 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User',
    required: true 
  }],
  chatType: { 
    type: String, 
    enum: ['direct', 'group', 'official'], 
    default: 'direct' 
  },
  title: { type: String, required: true },
  description: { type: String },
  groupPicture: { type: String },
  admins: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  lastMessage: { type: String, default: '' },
  lastMessageTime: { type: Date, default: Date.now },
  unreadCount: { type: Map, of: Number, default: {} },
  isActive: { type: Boolean, default: true },
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

chatSchema.index({ participants: 1 });
chatSchema.index({ lastMessageTime: -1 });
chatSchema.index({ chatType: 1 });

const Chat = mongoose.model('Chat', chatSchema);

// Message Schema
const messageSchema = new mongoose.Schema({
  chatId: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'Chat', 
    required: true 
  },
  senderId: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: true 
  },
  messageType: { 
    type: String, 
    enum: ['text', 'image', 'file', 'system', 'deleted'],
    default: 'text' 
  },
  content: { type: String, required: true },
  timestamp: { type: Date, default: Date.now },
  isRead: { type: Boolean, default: false },
  readBy: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  isDeleted: { type: Boolean, default: false },
  deletedAt: Date,
  deletedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  originalContent: { type: String }
});

messageSchema.index({ chatId: 1, timestamp: -1 });
messageSchema.index({ senderId: 1 });
messageSchema.index({ timestamp: -1 });

const Message = mongoose.model('Message', messageSchema);

// Friend Request Schema
const friendRequestSchema = new mongoose.Schema({
  fromUser: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: true 
  },
  toUser: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: true 
  },
  status: { 
    type: String, 
    enum: ['pending', 'accepted', 'rejected'], 
    default: 'pending' 
  },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

friendRequestSchema.index({ fromUser: 1, toUser: 1 });
friendRequestSchema.index({ toUser: 1, status: 1 });

const FriendRequest = mongoose.model('FriendRequest', friendRequestSchema);

// App Settings Schema
const appSettingsSchema = new mongoose.Schema({
  type: { type: String, default: 'default_settings' },
  language: { type: String, default: 'en' },
  theme: { type: String, default: 'white' },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

const AppSettings = mongoose.model('AppSettings', appSettingsSchema);

// Mourning Settings Schema
const mourningSettingsSchema = new mongoose.Schema({
  type: { type: String, default: 'mourning_settings' },
  isMourningPeriod: { type: Boolean, default: false },
  mourningMessage: { type: String, default: '' },
  mourningTheme: { type: String, default: 'black_ribbon' },
  startDate: { type: Date },
  endDate: { type: Date },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

const MourningSettings = mongoose.model('MourningSettings', mourningSettingsSchema);

// Recovery ID Schema
const recoveryIdSchema = new mongoose.Schema({
  userId: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: true 
  },
  recoveryId: { 
    type: String, 
    required: true, 
    unique: true 
  },
  securityQuestion: { type: String, required: true },
  securityAnswer: { type: String, required: true },
  isActive: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

recoveryIdSchema.index({ userId: 1 });
recoveryIdSchema.index({ recoveryId: 1 });

const RecoveryId = mongoose.model('RecoveryId', recoveryIdSchema);

// File Schema
const fileSchema = new mongoose.Schema({
  filename: { type: String, required: true, unique: true }, // The name on disk
  originalName: { type: String, required: true },
  mimetype: { type: String, required: true },
  size: { type: Number, required: true },
  url: { type: String, required: true },
  uploadedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  chatId: { type: mongoose.Schema.Types.ObjectId, ref: 'Chat', index: true },
  createdAt: { type: Date, default: Date.now }
});

fileSchema.index({ filename: 1 });

const File = mongoose.model('File', fileSchema);

// =============================================
// 📂 MEDIA UPLOAD TRACKING SCHEMAS
// =============================================

// MediaUpload Schema - สำหรับติดตามการอัพโหลด media content (วิดีโอ, รูปภาพ, ฯลฯ)
const mediaUploadSchema = new mongoose.Schema({
  uploadId: { type: String, unique: true, required: true, index: true }, // Unique identifier for tracking
  userId: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: true,
    index: true 
  },
  fileName: { type: String, required: true },
  fileType: { type: String, required: true }, // 'video', 'photo', 'camera'
  mimeType: { type: String, required: true },
  fileSize: { type: Number, required: true }, // in bytes
  title: { type: String, required: true },
  description: { type: String },
  filePath: { type: String, required: true }, // saved location
  fileUrl: { type: String }, // URL to access the file
  thumbnailUrl: { type: String }, // For videos
  duration: { type: Number }, // Video duration in seconds
  uploadProgress: { type: Number, default: 0 }, // 0-100%
  status: {
    type: String,
    enum: ['pending', 'uploading', 'completed', 'failed', 'cancelled'],
    default: 'pending',
    index: true
  },
  // ✅ ส่วนที่เพิ่มใหม่สำหรับ Post Settings
  visibility: {
    type: String,
    enum: ['public', 'friends', 'private'],
    default: 'public'
  },
  commentPermission: {
    type: String,
    enum: ['public', 'friends_followers', 'private'],
    default: 'public'
  },
  shareToStory: { type: Boolean, default: false },
  shareToGroups: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Chat' }],
  scheduledTime: { type: Date, sparse: true },
  collaborators: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  // ------------------------------------
  
  uploadedAt: { type: Date, default: Date.now },
  completedAt: { type: Date, sparse: true },
  cancelledAt: { type: Date, sparse: true },
  errorMessage: { type: String },
  retryCount: { type: Number, default: 0 },
  metadata: { type: Map, of: mongoose.Schema.Types.Mixed }
});

mediaUploadSchema.index({ userId: 1, uploadedAt: -1 });
mediaUploadSchema.index({ status: 1, uploadedAt: -1 });
mediaUploadSchema.index({ uploadId: 1 });

const MediaUpload = mongoose.model('MediaUpload', mediaUploadSchema);

// UploadProgress Schema - สำหรับให้ไคลเอนต์ติดตามความคืบหน้า
const uploadProgressSchema = new mongoose.Schema({
  uploadId: { type: String, unique: true, required: true, index: true },
  userId: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: true,
    index: true 
  },
  bytesUploaded: { type: Number, default: 0 },
  totalBytes: { type: Number, required: true },
  percentComplete: { type: Number, default: 0 }, // 0-100
  status: {
    type: String,
    enum: ['pending', 'uploading', 'paused', 'completed', 'failed', 'cancelled'],
    default: 'pending'
  },
  speed: { type: Number, default: 0 }, // bytes per second
  remainingTime: { type: Number, default: 0 }, // seconds
  startTime: { type: Date, default: Date.now },
  lastUpdateTime: { type: Date, default: Date.now },
  completedTime: { type: Date, sparse: true },
  errorMessage: { type: String },
  chunks: [{
    chunkIndex: { type: Number, required: true },
    size: { type: Number, required: true },
    status: { 
      type: String, 
      enum: ['pending', 'uploading', 'completed', 'failed'],
      default: 'pending'
    },
    uploadedAt: { type: Date }
  }]
});

uploadProgressSchema.index({ uploadId: 1 });
uploadProgressSchema.index({ userId: 1, uploadId: 1 });

const UploadProgress = mongoose.model('UploadProgress', uploadProgressSchema);

// Story Schema
const storySchema = new mongoose.Schema({
  userId: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: true,
    index: true 
  },
  type: { 
    type: String, 
    enum: ['text', 'image', 'video'], 
    default: 'text' 
  },
  mediaUrl: String,
  thumbnailUrl: String,
  backgroundColor: { type: String, default: '#000000' },
  textItems: [mongoose.Schema.Types.Mixed],
  stickers: [mongoose.Schema.Types.Mixed],
  visibility: {
    type: String,
    enum: ['public', 'friends', 'private', 'specific'],
    default: 'public'
  },
  specificViewers: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  allowComments: { type: Boolean, default: true },
  viewers: [{
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    viewedAt: { type: Date, default: Date.now }
  }],
  createdAt: { type: Date, default: Date.now },
  expiresAt: { type: Date, required: true, index: true }
});

// Auto-delete stories after expiration (TTL)
storySchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });
storySchema.index({ userId: 1, createdAt: -1 });

const Story = mongoose.model('Story', storySchema);

// =============================================
// �📨 NOTIFICATION SYSTEM
// =============================================

// Notification Schema
const notificationSchema = new mongoose.Schema({
  userId: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: true,
    index: true 
  },
  type: { 
    type: String, 
    enum: [
      'wallet_transaction',    // ธุรกรรมกระเป๋าเงิน
      'wallet_points',         // คะแนนคอยน์
      'chat_message',          // ข้อความใหม่
      'chat_call',             // การโทรเข้า
      'friend_request',        // คำขอเป็นเพื่อน
      'friend_accept',         // ยอมรับเพื่อน
      'profile_visit',         // มีคนเยี่ยมชมโปรไฟล์
      'profile_update',        // อัปเดตโปรไฟล์
      'bank_service',          // ใช้บริการธนาคาร
      'identity_verify',       // ยืนยันตัวตนสำเร็จ
      'system_alert',          // แจ้งเตือนระบบ
      'reward_earned'          // ได้รับรางวัล
    ],
    required: true,
    index: true
  },
  title: { 
    type: String, 
    required: true 
  },
  message: { 
    type: String, 
    required: true 
  },
  icon: { 
    type: String, 
    default: '🔔'
  },
  color: { 
    type: String, 
    default: '#1FAE4B'
  },
  data: { 
    type: Map, 
    of: mongoose.Schema.Types.Mixed,
    default: {}
  },
  isRead: { 
    type: Boolean, 
    default: false,
    index: true 
  },
  isArchived: { 
    type: Boolean, 
    default: false 
  },
  priority: { 
    type: String, 
    enum: ['low', 'medium', 'high', 'urgent'],
    default: 'medium'
  },
  expiresAt: { 
    type: Date,
    index: true,
    expires: 30 * 24 * 60 * 60 // 30 วัน
  },
  createdAt: { 
    type: Date, 
    default: Date.now,
    index: true 
  },
  readAt: { 
    type: Date 
  },
  sourceId: { 
    type: String 
  }
});

// ✅ Indexes สำหรับประสิทธิภาพ
notificationSchema.index({ userId: 1, isRead: 1, createdAt: -1 });
notificationSchema.index({ userId: 1, type: 1, createdAt: -1 });
notificationSchema.index({ sourceId: 1 });
notificationSchema.index({ userId: 1, isArchived: 1 });

const Notification = mongoose.model('Notification', notificationSchema);

// ✅ ฟังก์ชันสร้างการแจ้งเตือน
const createNotification = async ({
  userId,
  type,
  title,
  message,
  icon = '🔔',
  color = '#1FAE4B',
  data = {},
  priority = 'medium',
  sourceId = null
}) => {
  try {
    console.log('📨 Creating notification:', { userId, type, title });

    const notification = new Notification({
      userId,
      type,
      title,
      message,
      icon,
      color,
      data,
      priority,
      sourceId,
      expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000) // 30 วัน
    });

    await notification.save();
    
    // ✅ ส่ง Push Notification (ถ้ามี Firebase setup)
    await sendPushNotification(userId, {
      title,
      body: message,
      data: {
        type,
        ...data,
        notificationId: notification._id.toString()
      }
    });

    console.log('✅ Notification created:', notification._id);
    return notification;

  } catch (error) {
    console.error('❌ Error creating notification:', error);
    throw error;
  }
};

// ✅ ฟังก์ชันส่ง Push Notification
const sendPushNotification = async (userId, payload) => {
  try {
    const user = await User.findById(userId);
    if (!user || !user.fcmToken) {
      console.log('📤 User not found or no FCM token for user:', userId);
      return false;
    }
    const message = {
      token: user.fcmToken,
      notification: {
        title: payload.title,
        body: payload.body
      },
      data: payload.data
    };
    const response = await admin.messaging().send(message);
    console.log('📤 Push notification sent successfully:', response);
    return true;
  } catch (error) {
    console.error('❌ Error sending push notification:', error);
    return false;
  }
};

// =============================================
// 🏦 WALLET NOTIFICATIONS
// =============================================

// 💰 สร้างการแจ้งเตือนธุรกรรมกระเป๋าเงิน
const createWalletTransactionNotification = async (userId, transactionData) => {
  const { bankName, serviceType, amount, time, referenceId } = transactionData;
  
  let title, message, icon, color;
  
  switch (serviceType) {
    case 'scan_pay':
      title = 'แสกนจ่าย';
      message = `${bankName} เวลา ${time}`;
      icon = '💰';
      color = '#4CAF50'; // สีเขียว
      break;
    case 'transfer':
      title = 'โอนเงิน';
      message = `${bankName} จำนวน ${amount} THB`;
      icon = '💸';
      color = '#2196F3'; // สีฟ้า
      break;
    case 'topup':
      title = 'เติมเงิน';
      message = `${bankName} จำนวน ${amount} THB`;
      icon = '📈';
      color = '#FF9800'; // สีส้ม
      break;
    case 'withdraw':
      title = 'ถอนเงิน';
      message = `${bankName} จำนวน ${amount} THB`;
      icon = '🏧';
      color = '#9C27B0'; // สีม่วง
      break;
    default:
      title = 'ธุรกรรมกระเป๋าเงิน';
      message = `${bankName} - ${serviceType}`;
      icon = '💳';
      color = '#607D8B'; // สีเทา
  }

  return await createNotification({
    userId,
    type: 'wallet_transaction',
    title,
    message,
    icon,
    color,
    data: {
      bankName,
      serviceType,
      amount,
      time,
      referenceId,
      timestamp: new Date().toISOString()
    },
    priority: 'high',
    sourceId: `wallet_${referenceId}`
  });
};

// 🎯 สร้างการแจ้งเตือนคะแนนคอยน์
const createCoinPointsNotification = async (userId, pointsData) => {
  const { points, description, balanceAfter, type } = pointsData;
  
  let title, message, icon;
  
  if (type === 'earn') {
    title = 'ได้รับคะแนนคอยน์';
    message = `+${points} คะแนน (${description})`;
    icon = '⭐';
  } else if (type === 'redeem') {
    title = 'ใช้คะแนนคอยน์';
    message = `-${points} คะแนน (${description})`;
    icon = '🎁';
  } else {
    title = 'คะแนนคอยน์';
    message = `${description}`;
    icon = '🪙';
  }

  return await createNotification({
    userId,
    type: 'wallet_points',
    title,
    message,
    icon,
    color: type === 'earn' ? '#FFC107' : '#E91E63',
    data: {
      points,
      description,
      balanceAfter,
      type,
      timestamp: new Date().toISOString()
    },
    priority: 'medium',
    sourceId: `points_${Date.now()}`
  });
};

// =============================================
// 💬 CHAT NOTIFICATIONS
// =============================================

// 💬 สร้างการแจ้งเตือนข้อความใหม่
const createChatMessageNotification = async (userId, chatData) => {
  const { senderName, message, chatId, messageType } = chatData;
  
  let icon = '💬';
  let title = 'ข้อความใหม่';
  
  if (messageType === 'image') {
    icon = '🖼️';
    title = 'รูปภาพใหม่';
  } else if (messageType === 'voice') {
    icon = '🎤';
    title = 'ข้อความเสียง';
  } else if (messageType === 'video') {
    icon = '🎥';
    title = 'วิดีโอใหม่';
  }

  return await createNotification({
    userId,
    type: 'chat_message',
    title: `${senderName}: ${title}`,
    message: messageType === 'text' ? message : `ส่ง${title.toLowerCase()}`,
    icon,
    color: '#1FAE4B', // สีเขียว Connect
    data: {
      senderName,
      message,
      chatId,
      messageType,
      timestamp: new Date().toISOString()
    },
    priority: 'urgent',
    sourceId: `chat_${chatId}_${Date.now()}`
  });
};

// 📞 สร้างการแจ้งเตือนการโทรเข้า
const createCallNotification = async (userId, callData) => {
  const { callerName, callType, callId } = callData;
  
  const title = callType === 'video' ? 'วิดีโอคอลล์เข้า' : 'โทรศัพท์เข้า';
  const icon = callType === 'video' ? '🎥' : '📞';

  return await createNotification({
    userId,
    type: 'chat_call',
    title: `${callerName}: ${title}`,
    message: callType === 'video' ? 'วิดีโอคอลล์...' : 'กำลังโทร...',
    icon,
    color: '#FF5722', // สีส้ม
    data: {
      callerName,
      callType,
      callId,
      timestamp: new Date().toISOString()
    },
    priority: 'urgent',
    sourceId: `call_${callId}`
  });
};

// =============================================
// 👥 FRIEND NOTIFICATIONS
// =============================================

// 👥 สร้างการแจ้งเตือนคำขอเป็นเพื่อน
const createFriendRequestNotification = async (userId, friendData) => {
  const { requesterName, requesterId } = friendData;

  return await createNotification({
    userId,
    type: 'friend_request',
    title: 'คำขอเป็นเพื่อน',
    message: `${requesterName} ส่งคำขอเป็นเพื่อน`,
    icon: '👤',
    color: '#3F51B5', // สีน้ำเงิน
    data: {
      requesterName,
      requesterId,
      timestamp: new Date().toISOString()
    },
    priority: 'high',
    sourceId: `friend_request_${requesterId}`
  });
};

// 🤝 สร้างการแจ้งเตือนยอมรับเพื่อน
const createFriendAcceptNotification = async (userId, friendData) => {
  const { friendName, friendId } = friendData;

  return await createNotification({
    userId,
    type: 'friend_accept',
    title: 'ยอมรับคำขอเป็นเพื่อน',
    message: `${friendName} ยอมรับคำขอเป็นเพื่อนแล้ว`,
    icon: '🤝',
    color: '#4CAF50', // สีเขียว
    data: {
      friendName,
      friendId,
      timestamp: new Date().toISOString()
    },
    priority: 'medium',
    sourceId: `friend_accept_${friendId}`
  });
};

// =============================================
// 👤 PROFILE NOTIFICATIONS
// =============================================

// 👁️ สร้างการแจ้งเตือนคนเยี่ยมชมโปรไฟล์
const createProfileVisitNotification = async (userId, visitorData) => {
  const { visitorName, visitorId } = visitorData;

  return await createNotification({
    userId,
    type: 'profile_visit',
    title: 'มีคนเยี่ยมชมโปรไฟล์',
    message: `${visitorName} เยี่ยมชมโปรไฟล์ของคุณ`,
    icon: '👁️',
    color: '#9C27B0', // สีม่วง
    data: {
      visitorName,
      visitorId,
      timestamp: new Date().toISOString()
    },
    priority: 'low',
    sourceId: `profile_visit_${visitorId}_${Date.now()}`
  });
};

// ✏️ สร้างการแจ้งเตือนอัปเดตโปรไฟล์
const createProfileUpdateNotification = async (userId, updateData) => {
  const { field, oldValue, newValue } = updateData;

  return await createNotification({
    userId,
    type: 'profile_update',
    title: 'อัปเดตโปรไฟล์สำเร็จ',
    message: `${field} ถูกเปลี่ยนจาก "${oldValue}" เป็น "${newValue}"`,
    icon: '✏️',
    color: '#FF9800', // สีส้ม
    data: {
      field,
      oldValue,
      newValue,
      timestamp: new Date().toISOString()
    },
    priority: 'low',
    sourceId: `profile_update_${Date.now()}`
  });
};

// =============================================
// 🏦 BANK SERVICE NOTIFICATIONS
// =============================================

// 🏦 สร้างการแจ้งเตือนใช้บริการธนาคาร
const createBankServiceNotification = async (userId, bankData) => {
  const { bankName, serviceType, deeplinkUrl } = bankData;

  const serviceNames = {
    'scan_pay': 'แสกนจ่าย',
    'transfer': 'โอนเงิน',
    'topup': 'เติมเงิน',
    'withdraw': 'ถอนเงินสด'
  };

  const serviceName = serviceNames[serviceType] || 'บริการธนาคาร';

  return await createNotification({
    userId,
    type: 'bank_service',
    title: 'เริ่มใช้บริการธนาคาร',
    message: `${bankName} - ${serviceName}`,
    icon: '🏦',
    color: '#2196F3', // สีฟ้า
    data: {
      bankName,
      serviceType,
      serviceName,
      deeplinkUrl,
      timestamp: new Date().toISOString()
    },
    priority: 'high',
    sourceId: `bank_${bankName}_${Date.now()}`
  });
};

// =============================================
// 🆔 IDENTITY VERIFICATION NOTIFICATIONS
// =============================================

// ✅ สร้างการแจ้งเตือนยืนยันตัวตนสำเร็จ
const createIdentityVerificationNotification = async (userId, verificationData) => {
  const { method, rewardPoints } = verificationData;

  const methodNames = {
    'id_card': 'บัตรประชาชน',
    'passport': 'พาสปอร์ต'
  };

  const methodName = methodNames[method] || 'ยืนยันตัวตน';

  return await createNotification({
    userId,
    type: 'identity_verify',
    title: 'ยืนยันตัวตนสำเร็จ! 🎉',
    message: `ยืนยันตัวตนด้วย${methodName} สำเร็จ ได้รับ ${rewardPoints} คะแนน`,
    icon: '✅',
    color: '#4CAF50', // สีเขียว
    data: {
      method,
      methodName,
      rewardPoints,
      timestamp: new Date().toISOString()
    },
    priority: 'high',
    sourceId: `identity_verify_${userId}`
  });
};

// =============================================
// 🎁 REWARD NOTIFICATIONS
// =============================================

// 🎁 สร้างการแจ้งเตือนได้รับรางวัล
const createRewardNotification = async (userId, rewardData) => {
  const { rewardName, points, description } = rewardData;

  return await createNotification({
    userId,
    type: 'reward_earned',
    title: 'ได้รับรางวัล! 🎁',
    message: `${rewardName} - ${description}`,
    icon: '🎁',
    color: '#FFC107', // สีเหลือง
    data: {
      rewardName,
      points,
      description,
      timestamp: new Date().toISOString()
    },
    priority: 'medium',
    sourceId: `reward_${Date.now()}`
  });
};

// =============================================
// 🚨 SYSTEM ALERT NOTIFICATIONS
// =============================================

// ⚡ สร้างการแจ้งเตือนระบบ
const createSystemNotification = async (userId, systemData) => {
  const { alertType, message, actionUrl } = systemData;

  return await createNotification({
    userId,
    type: 'system_alert',
    title: 'แจ้งเตือนระบบ',
    message,
    icon: '⚡',
    color: '#FF5722', // สีแดงส้ม
    data: {
      alertType,
      actionUrl,
      timestamp: new Date().toISOString()
    },
    priority: alertType === 'critical' ? 'urgent' : 'high',
    sourceId: `system_${Date.now()}`
  });
};

// =============================================
// 🔧 UTILITY FUNCTIONS
// =============================================

const escapeRegex = (text) => {
  // Escape special characters for MongoDB regex to prevent ReDoS and Injection
  return text.replace(/[-[\]{}()*+?.,\\^$|#\s]/g, "\\$&");
};

const _getTimeAgo = (date) => {
  const now = new Date();
  const diffMs = now - date;
  const diffSec = Math.floor(diffMs / 1000);
  const diffMin = Math.floor(diffSec / 60);
  const diffHour = Math.floor(diffMin / 60);
  const diffDay = Math.floor(diffHour / 24);
  
  if (diffSec < 60) return 'เมื่อสักครู่';
  if (diffMin < 60) return `${diffMin} นาทีที่แล้ว`;
  if (diffHour < 24) return `${diffHour} ชั่วโมงที่แล้ว`;
  if (diffDay === 1) return 'เมื่อวานนี้';
  if (diffDay < 7) return `${diffDay} วันที่แล้ว`;
  if (diffDay < 30) return `${Math.floor(diffDay / 7)} สัปดาห์ที่แล้ว`;
  if (diffDay < 365) return `${Math.floor(diffDay / 30)} เดือนที่แล้ว`;
  return `${Math.floor(diffDay / 365)} ปีที่แล้ว`;
};

const generateRecoveryId = () => {
  const timestamp = Date.now().toString(36);
  const random = Math.random().toString(36).substr(2, 5);
  return `REC${timestamp}${random}`.toUpperCase();
};

const generateUserId = async () => {
  let userId;
  let attempts = 0;
  do {
    userId = 'USR' + Math.random().toString(36).substr(2, 8).toUpperCase();
    attempts++;
    if (attempts > 10) throw new Error('Unable to generate unique userId');
  } while (await User.findOne({ userId }));
  return userId;
};

const generateSalt = () => bcrypt.genSaltSync(12);
const hashPassword = (password, salt) => bcrypt.hashSync(password + salt, 12);
const verifyPassword = (password, hash, salt) => bcrypt.compareSync(password + salt, hash);
const generateAuthToken = (userId) => jwt.sign({ userId }, JWT_SECRET, { expiresIn: '30d' });

const createUserWallet = async (userId) => {
  try {
    const existingWallet = await Wallet.findOne({ userId });
    
    if (!existingWallet) {
      const newWallet = new Wallet({
        userId: userId,
        balance: 0.0,
        coinPoints: 0,
        currency: 'THB'
      });
      
      await newWallet.save();
      console.log('✅ Wallet created for user:', userId);
      return newWallet;
    }
    
    return existingWallet;
  } catch (error) {
    console.error('❌ Error creating wallet:', error);
    throw error;
  }
};

const initializeBankServices = async () => {
  try {
    const bankServices = [
      {
        code: 'bank_a',
        name: 'บริการธนาคาร A',
        nameEn: 'Bank Service A',
        nameZh: '银行服务A',
        color: '#1E88E5',
        icon: 'account_balance',
        deeplink: {
          scan_pay: 'kbank://qr/payment',
          transfer: 'kbank://transfer/money',
          topup: 'kbank://wallet/topup',
          withdraw: 'kbank://account/withdraw'
        },
        packageName: 'com.kasikorn.retail'
      },
      {
        code: 'bank_b',
        name: 'บริการธนาคาร B',
        nameEn: 'Bank Service B',
        nameZh: '银行服务B',
        color: '#43A047',
        icon: 'account_balance',
        deeplink: {
          scan_pay: 'scbeasy://payment/scan',
          transfer: 'scbeasy://transfer/money',
          topup: 'scbeasy://account/deposit',
          withdraw: 'scbeasy://withdraw/cash'
        },
        packageName: 'com.scb.phone'
      },
      {
        code: 'bank_c',
        name: 'บริการธนาคาร C',
        nameEn: 'Bank Service C',
        nameZh: '银行服务C',
        color: '#FB8C00',
        icon: 'account_balance',
        deeplink: {
          scan_pay: 'bbl://qr/pay',
          transfer: 'bbl://fund/transfer',
          topup: 'bbl://wallet/add',
          withdraw: 'bbl://cash/withdraw'
        },
        packageName: 'com.bbl.mobilebanking'
      },
      {
        code: 'bank_d',
        name: 'บริการธนาคาร D',
        nameEn: 'Bank Service D',
        nameZh: '银行服务D',
        color: '#8E24AA',
        icon: 'account_balance',
        deeplink: {
          scan_pay: 'krungsri://payment/qrcode',
          transfer: 'krungsri://send/money',
          topup: 'krungsri://deposit/money',
          withdraw: 'krungsri://get/cash'
        },
        packageName: 'com.krungsri.ibanking'
      },
      {
        code: 'bank_e',
        name: 'บริการธนาคาร E',
        nameEn: 'Bank Service E',
        nameZh: '银行服务E',
        color: '#E53935',
        icon: 'account_balance',
        deeplink: {
          scan_pay: 'baac://qr/payment',
          transfer: 'baac://transfer/money',
          topup: 'baac://wallet/topup',
          withdraw: 'baac://account/withdraw'
        },
        packageName: 'com.baac.bank'
      },
      {
        code: 'bank_f',
        name: 'บริการธนาคาร F',
        nameEn: 'Bank Service F',
        nameZh: '银行服务F',
        color: '#795548',
        icon: 'account_balance',
        deeplink: {
          scan_pay: 'ktb://app/main',
          transfer: 'ktb://app/transfer',
          topup: 'ktb://app/topup',
          withdraw: 'ktb://app/withdraw'
        },
        packageName: 'ktbcs.netbank'
      }
    ];

    for (const bankData of bankServices) {
      const existingBank = await BankService.findOne({ code: bankData.code });
      
      if (!existingBank) {
        await BankService.create(bankData);
        console.log('✅ Bank service created:', bankData.code);
      }
    }
    
    console.log('✅ Bank services initialized successfully');
  } catch (error) {
    console.error('❌ Error initializing bank services:', error);
  }
};

const createSystemAccount = async () => {
  try {
    const existingSystem = await User.findOne({ userType: 'system', email: 'system@connect.app' });
    
    if (!existingSystem) {
      const salt = generateSalt();
      const systemUser = new User({
        username: 'Connect Support',
        email: 'system@connect.app',
        passwordHash: hashPassword('support123', salt),
        passwordSalt: salt,
        userType: 'system',
        userId: 'support',
        settings: {
          language: 'en',
          theme: 'white'
        }
      });
      
      await systemUser.save();
      await createUserWallet(systemUser._id);
      console.log('✅ System account created successfully');
    } else {
      console.log('✅ System account already exists');
    }
  } catch (error) {
    console.error('❌ Error creating system account:', error);
  }
};

const createAdminUser = async () => {
  try {
    const existingAdmin = await User.findOne({ userType: 'admin' });
    if (!existingAdmin) {
      const salt = generateSalt();
      const adminUser = new User({
        username: 'Admin',
        email: 'admin@connect.app',
        passwordHash: hashPassword('admin123', salt),
        passwordSalt: salt,
        userType: 'admin',
        userId: await generateUserId()
      });
      await adminUser.save();
      await createUserWallet(adminUser._id);
      console.log('✅ Admin user created');
      
      const adminToken = generateAuthToken(adminUser._id);
      console.log('🔑 Admin Token:', adminToken);
    } else {
      console.log('✅ Admin user already exists');
    }
  } catch (error) {
    console.error('❌ Error creating admin user:', error);
  }
};

const createOfficialChat = async (userId) => {
  try {
    const systemUser = await User.findOne({ userType: 'system' });
    
    if (!systemUser) {
      console.error('❌ System user not found');
      return;
    }

    const existingOfficialChats = await Chat.find({
      participants: { 
        $all: [userId, systemUser._id]
      },
      chatType: 'official',
      isActive: true
    }).sort({ createdAt: -1 });

    if (existingOfficialChats.length === 0) {
      const officialChat = new Chat({
        participants: [userId, systemUser._id],
        chatType: 'official',
        title: 'Connect Support',
        lastMessage: 'สวัสดี! ยินดีต้อนรับสู่ Connect App เราพร้อมให้ความช่วยเหลือเสมอ',
        lastMessageTime: new Date(),
        createdBy: systemUser._id
      });

      await officialChat.save();

      const welcomeMessage = new Message({
        chatId: officialChat._id,
        senderId: systemUser._id,
        messageType: 'system',
        content: 'สวัสดี! ยินดีต้อนรับสู่ Connect App เราพร้อมให้ความช่วยเหลือเสมอ 😊\n\nคุณสามารถสอบถามเกี่ยวกับการใช้งานแอป หรือรายงานปัญหาต่างๆ ได้ที่นี่'
      });

      await welcomeMessage.save();
      console.log('✅ Official chat created for user:', userId);
    } else if (existingOfficialChats.length > 1) {
      console.log(`🔄 Found ${existingOfficialChats.length} official chats for user ${userId}, cleaning duplicates...`);
      
      const latestChat = existingOfficialChats[0];
      const chatsToDelete = existingOfficialChats.slice(1);
      
      for (const chat of chatsToDelete) {
        await Message.deleteMany({ chatId: chat._id });
        await Chat.deleteOne({ _id: chat._id });
        console.log(`🗑️ Deleted duplicate official chat: ${chat._id}`);
      }
      
      console.log(`✅ Kept latest official chat: ${latestChat._id} for user: ${userId}`);
    } else {
      console.log('✅ Official chat already exists for user:', userId, 'chatId:', existingOfficialChats[0]._id);
    }
  } catch (error) {
    console.error('❌ Error creating official chat:', error);
  }
};

const initializeMourningSettings = async () => {
  try {
    let mourningSettings = await MourningSettings.findOne({ type: 'mourning_settings' });
    
    if (!mourningSettings) {
      mourningSettings = await MourningSettings.create({
        type: 'mourning_settings',
        isMourningPeriod: false,
        mourningMessage: '',
        mourningTheme: 'black_ribbon',
        startDate: null,
        endDate: null
      });
      console.log('✅ Mourning settings initialized');
    }

    const now = new Date();
    if (mourningSettings.isMourningPeriod && mourningSettings.endDate && now > mourningSettings.endDate) {
      mourningSettings.isMourningPeriod = false;
      mourningSettings.mourningMessage = '';
      await mourningSettings.save();
      console.log('🕊️ Mourning period has ended');
    }

    return mourningSettings;
  } catch (error) {
    console.error('❌ Error initializing mourning settings:', error);
    return null;
  }
};

const sendRecoveryEmail = async (email, recoveryId, securityQuestion) => {
  console.log('📧 Recovery ID Created:', {
    email: email,
    recoveryId: recoveryId,
    securityQuestion: securityQuestion
  });
  return true;
};

// =============================================
// 🔐 AUTHENTICATION MIDDLEWARE
// =============================================

const authenticateToken = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    
    if (!token) {
      return res.status(401).json({ error: 'Access token required' });
    }

    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.userId);
    
    if (!user) {
      return res.status(401).json({ error: 'Invalid token' });
    }

    req.user = user;
    next();
  } catch (error) {
    return res.status(401).json({ error: 'Invalid token' });
  }
};

// =============================================
// ✅ INPUT VALIDATION MIDDLEWARE
// =============================================

const validateRegistration = [
  body('username')
    .isLength({ min: 3, max: 30 })
    .withMessage('Username must be between 3-30 characters')
    .trim()
    .escape(),
  body('email')
    .isEmail()
    .withMessage('Must be a valid email')
    .normalizeEmail(),
  body('password')
    .isLength({ min: 6 })
    .withMessage('Password must be at least 6 characters'),
  body('phone')
    .optional()
    .isLength({ min: 10, max: 15 })
    .withMessage('Phone number must be between 10-15 characters')
    .matches(/^[0-9]+$/)
    .withMessage('Phone number must contain only numbers'),
  body('pdpa_consent')
    .isBoolean()
    .withMessage('PDPA consent must be a boolean value')
    .equals('true')
    .withMessage('PDPA consent is required for registration')
];

const validateLogin = [
  body('email')
    .isEmail()
    .withMessage('Must be a valid email')
    .normalizeEmail(),
  body('password')
    .notEmpty()
    .withMessage('Password is required')
];

// =============================================
// 🚀 API ROUTES - WALLET & IDENTITY
// =============================================

// 💰 Get Wallet Information
app.get('/api/wallet', authenticateToken, async (req, res) => {
  try {
    console.log('💰 Fetching wallet for user:', req.user._id);

    const wallet = await Wallet.findOne({ userId: req.user._id });
    
    if (!wallet) {
      const newWallet = await createUserWallet(req.user._id);
      return res.json({
        success: true,
        wallet: {
          balance: newWallet.balance,
          coinPoints: newWallet.coinPoints,
          currency: newWallet.currency
        }
      });
    }

    const identityVerification = await IdentityVerification.findOne({ 
      userId: req.user._id 
    });

    res.json({
      success: true,
      wallet: {
        balance: wallet.balance,
        coinPoints: wallet.coinPoints,
        currency: wallet.currency
      },
      identityVerification: identityVerification ? {
        status: identityVerification.status,
        verificationMethod: identityVerification.verificationMethod,
        verifiedAt: identityVerification.verifiedAt
      } : null
    });

  } catch (error) {
    console.error('❌ Get wallet error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch wallet information'
    });
  }
});

// 💰 Get Transaction History
app.get('/api/wallet/transactions', authenticateToken, async (req, res) => {
  try {
    const { page = 1, limit = 20 } = req.query;
    const skip = (page - 1) * limit;

    console.log('📋 Fetching transactions for user:', req.user._id);

    const wallet = await Wallet.findOne({ userId: req.user._id });
    if (!wallet) {
      return res.status(404).json({
        success: false,
        error: 'Wallet not found'
      });
    }

    const transactions = await Transaction.find({ 
      userId: req.user._id 
    })
    .sort({ createdAt: -1 })
    .skip(skip)
    .limit(parseInt(limit));

    const total = await Transaction.countDocuments({ userId: req.user._id });

    res.json({
      success: true,
      transactions: transactions.map(tx => ({
        id: tx._id,
        type: tx.type,
        amount: tx.amount,
        currency: tx.currency,
        description: tx.description,
        status: tx.status,
        referenceId: tx.referenceId,
        createdAt: tx.createdAt,
        metadata: tx.metadata
      })),
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / limit)
      }
    });

  } catch (error) {
    console.error('❌ Get transactions error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch transactions'
    });
  }
});

// 💰 Get Reward History
app.get('/api/wallet/rewards', authenticateToken, async (req, res) => {
  try {
    const { page = 1, limit = 20 } = req.query;
    const skip = (page - 1) * limit;

    console.log('🎁 Fetching rewards for user:', req.user._id);

    const rewards = await Reward.find({ 
      userId: req.user._id 
    })
    .sort({ createdAt: -1 })
    .skip(skip)
    .limit(parseInt(limit));

    const total = await Reward.countDocuments({ userId: req.user._id });

    res.json({
      success: true,
      rewards: rewards.map(reward => ({
        id: reward._id,
        type: reward.type,
        points: reward.points,
        description: reward.description,
        balanceAfter: reward.balanceAfter,
        referenceId: reward.referenceId,
        createdAt: reward.createdAt,
        metadata: reward.metadata
      })),
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / limit)
      }
    });

  } catch (error) {
    console.error('❌ Get rewards error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch rewards'
    });
  }
});

// 💰 Add Coin Points
app.post('/api/wallet/add-coins', authenticateToken, [
  body('points')
    .isInt({ min: 1, max: 10000 })
    .withMessage('Points must be between 1-10000'),
  body('description')
    .notEmpty()
    .withMessage('Description is required')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        error: errors.array()[0].msg
      });
    }

    const { points, description } = req.body;

    console.log('💰 Adding coin points for user:', req.user._id, 'points:', points);

    const wallet = await Wallet.findOne({ userId: req.user._id });
    if (!wallet) {
      return res.status(404).json({
        success: false,
        error: 'Wallet not found'
      });
    }

    wallet.coinPoints += points;
    await wallet.save();

    const reward = new Reward({
      userId: req.user._id,
      type: 'earn',
      points: points,
      description: description,
      balanceAfter: wallet.coinPoints,
      referenceId: `MANUAL_${Date.now()}`
    });
    await reward.save();

    // ✅ เพิ่มการแจ้งเตือนคะแนนคอยน์
    await createCoinPointsNotification(req.user._id, {
      points: points,
      description: description,
      balanceAfter: wallet.coinPoints,
      type: 'earn'
    });

    console.log('✅ Coin points added successfully:', {
      userId: req.user._id,
      pointsAdded: points,
      newBalance: wallet.coinPoints
    });

    res.json({
      success: true,
      message: 'Coin points added successfully',
      pointsAdded: points,
      newBalance: wallet.coinPoints,
      rewardId: reward._id
    });

  } catch (error) {
    console.error('❌ Add coin points error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to add coin points'
    });
  }
});

// 🆔 Start Identity Verification - FIXED VERSION
app.post('/api/identity/verify', authenticateToken, [
  body('verificationMethod')
    .isIn(['id_card', 'passport'])
    .withMessage('Verification method must be id_card or passport'),
  body('documentNumber')
    .notEmpty()
    .withMessage('Document number is required')
    .isLength({ min: 1, max: 50 })
    .withMessage('Document number must be between 1-50 characters'),
  body('fullName')
    .notEmpty()
    .withMessage('Full name is required')
    .isLength({ min: 2, max: 100 })
    .withMessage('Full name must be between 2-100 characters'),
  body('birthDate')
    .optional()
    .matches(/^\d{1,2}\/\d{1,2}\/\d{4}$/)
    .withMessage('Birth date must be in format DD/MM/YYYY'),
  body('nationality')
    .optional()
    .isLength({ min: 2, max: 50 })
    .withMessage('Nationality must be between 2-50 characters'),
  body('expiryDate')
    .optional()
    .matches(/^\d{1,2}\/\d{1,2}\/\d{4}$/)
    .withMessage('Expiry date must be in format DD/MM/YYYY')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        error: errors.array()[0].msg
      });
    }

    const { 
      verificationMethod, 
      documentNumber, 
      fullName, 
      birthDate, 
      nationality, 
      expiryDate 
    } = req.body;

    console.log('🆔 Starting identity verification for user:', req.user._id, {
      verificationMethod,
      documentNumber: documentNumber ? `${documentNumber.substring(0, 5)}...` : 'empty',
      fullName: fullName ? `${fullName.substring(0, 10)}...` : 'empty',
      birthDate,
      nationality,
      expiryDate
    });

    // ✅ ตรวจสอบว่าผู้ใช้มีการยืนยันตัวตนที่กำลังดำเนินการหรือเสร็จสิ้นแล้ว
    const existingVerification = await IdentityVerification.findOne({ 
      userId: req.user._id,
      status: { $in: ['pending', 'verified'] }
    });

    if (existingVerification) {
      console.log('⚠️ Identity verification already exists:', existingVerification.status);
      return res.status(400).json({
        success: false,
        error: 'Identity verification already in progress or completed'
      });
    }

    // ✅ เตรียมข้อมูลการยืนยันตัวตน
    const verificationData = {
      userId: req.user._id,
      verificationMethod,
      documentNumber: documentNumber.trim(),
      fullName: fullName.trim(),
      status: 'pending',
      faceScanData: {
        stepsCompleted: 0,
        totalSteps: 6,
        scanResults: [],
        completedAt: null
      }
    };

    // ✅ เพิ่มข้อมูลเพิ่มเติมตามประเภทการยืนยัน
    if (verificationMethod === 'id_card') {
      if (birthDate) {
        try {
          // แปลงรูปแบบวันที่จาก DD/MM/YYYY เป็น ISO
          const [day, month, year] = birthDate.split('/');
          if (day && month && year) {
            const isoDate = new Date(`${year}-${month.padStart(2, '0')}-${day.padStart(2, '0')}`);
            verificationData.birthDate = isoDate;
            console.log('✅ Converted birth date:', birthDate, '->', isoDate);
          }
        } catch (dateError) {
          console.warn('⚠️ Invalid birth date format, skipping:', birthDate);
        }
      }
    } else if (verificationMethod === 'passport') {
      if (nationality) {
        verificationData.nationality = nationality.trim();
      }
      if (expiryDate) {
        try {
          const [day, month, year] = expiryDate.split('/');
          if (day && month && year) {
            const isoDate = new Date(`${year}-${month.padStart(2, '0')}-${day.padStart(2, '0')}`);
            verificationData.expiryDate = isoDate;
            console.log('✅ Converted expiry date:', expiryDate, '->', isoDate);
          }
        } catch (dateError) {
          console.warn('⚠️ Invalid expiry date format, skipping:', expiryDate);
        }
      }
    }

    console.log('📝 Creating identity verification with data:', {
      verificationMethod: verificationData.verificationMethod,
      hasDocumentNumber: !!verificationData.documentNumber,
      hasFullName: !!verificationData.fullName,
      hasBirthDate: !!verificationData.birthDate,
      hasNationality: !!verificationData.nationality,
      hasExpiryDate: !!verificationData.expiryDate
    });

    // ✅ สร้างการยืนยันตัวตนใหม่
    const identityVerification = new IdentityVerification(verificationData);
    await identityVerification.save();

    console.log('✅ Identity verification started successfully:', {
      verificationId: identityVerification._id,
      userId: req.user._id,
      method: verificationMethod
    });

    res.json({
      success: true,
      message: 'Identity verification started successfully',
      verificationId: identityVerification._id,
      nextStep: 'face_scan'
    });

  } catch (error) {
    console.error('❌ Start identity verification error:', error);
    
    // ✅ ให้ข้อมูล error ที่ละเอียดมากขึ้น
    let errorMessage = 'Failed to start identity verification';
    if (error.name === 'ValidationError') {
      errorMessage = `Data validation error: ${Object.values(error.errors).map(e => e.message).join(', ')}`;
    } else if (error.code === 11000) {
      errorMessage = 'Identity verification already exists for this user';
    }

    res.status(500).json({
      success: false,
      error: errorMessage,
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// 🆔 Update Face Scan Progress
app.post('/api/identity/face-scan/:verificationId', authenticateToken, [
  body('step')
    .isInt({ min: 1, max: 6 })
    .withMessage('Step must be between 1-6'),
  body('status')
    .isIn(['completed', 'failed'])
    .withMessage('Status must be completed or failed'),
  body('title')
    .notEmpty()
    .withMessage('Title is required')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        error: errors.array()[0].msg
      });
    }

    const { verificationId } = req.params;
    const { step, status, title } = req.body;

    console.log('📸 Updating face scan progress:', { verificationId, step, status });

    const identityVerification = await IdentityVerification.findOne({
      _id: verificationId,
      userId: req.user._id
    });

    if (!identityVerification) {
      return res.status(404).json({
        success: false,
        error: 'Identity verification not found'
      });
    }

    const scanResult = {
      step: step,
      title: title,
      status: status,
      timestamp: new Date()
    };

    const existingStepIndex = identityVerification.faceScanData.scanResults.findIndex(
      result => result.step === step
    );

    if (existingStepIndex >= 0) {
      identityVerification.faceScanData.scanResults[existingStepIndex] = scanResult;
    } else {
      identityVerification.faceScanData.scanResults.push(scanResult);
    }

    identityVerification.faceScanData.stepsCompleted = 
      identityVerification.faceScanData.scanResults.filter(
        result => result.status === 'completed'
      ).length;

    if (identityVerification.faceScanData.stepsCompleted === 6) {
      identityVerification.faceScanData.completedAt = new Date();
      identityVerification.status = 'verified';
      identityVerification.verifiedAt = new Date();
      
      const wallet = await Wallet.findOne({ userId: req.user._id });
      if (wallet) {
        const rewardPoints = 100;
        wallet.coinPoints += rewardPoints;
        await wallet.save();

        const reward = new Reward({
          userId: req.user._id,
          type: 'earn',
          points: rewardPoints,
          description: 'รางวัลการยืนยันตัวตนสำเร็จ',
          balanceAfter: wallet.coinPoints,
          referenceId: `VERIFY_${verificationId}`
        });
        await reward.save();

        // ✅ สร้างการแจ้งเตือนยืนยันตัวตนสำเร็จ
        await createIdentityVerificationNotification(req.user._id, {
          method: identityVerification.verificationMethod,
          rewardPoints: rewardPoints
        });
      }
    }

    await identityVerification.save();

    console.log('✅ Face scan progress updated:', {
      stepsCompleted: identityVerification.faceScanData.stepsCompleted,
      totalSteps: identityVerification.faceScanData.totalSteps
    });

    res.json({
      success: true,
      message: 'Face scan progress updated successfully',
      progress: {
        stepsCompleted: identityVerification.faceScanData.stepsCompleted,
        totalSteps: identityVerification.faceScanData.totalSteps,
        isCompleted: identityVerification.faceScanData.stepsCompleted === 6,
        status: identityVerification.status
      }
    });

  } catch (error) {
    console.error('❌ Update face scan error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to update face scan progress'
    });
  }
});

// 🆔 Get Identity Verification Status
app.get('/api/identity/status', authenticateToken, async (req, res) => {
  try {
    console.log('🆔 Getting identity verification status for user:', req.user._id);

    const identityVerification = await IdentityVerification.findOne({ 
      userId: req.user._id 
    });

    if (!identityVerification) {
      return res.json({
        success: true,
        hasVerification: false,
        status: 'not_started'
      });
    }

    res.json({
      success: true,
      hasVerification: true,
      status: identityVerification.status,
      verificationMethod: identityVerification.verificationMethod,
      progress: {
        stepsCompleted: identityVerification.faceScanData.stepsCompleted,
        totalSteps: identityVerification.faceScanData.totalSteps,
        isCompleted: identityVerification.faceScanData.stepsCompleted === 6
      },
      verifiedAt: identityVerification.verifiedAt,
      documentNumber: identityVerification.documentNumber,
      fullName: identityVerification.fullName
    });

  } catch (error) {
    console.error('❌ Get identity status error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to get identity verification status'
    });
  }
});

// 💳 Get Bank Services
app.get('/api/bank/services', authenticateToken, async (req, res) => {
  try {
    console.log('💳 Fetching bank services for user:', req.user._id);

    const bankServices = await BankService.find({ isActive: true })
    .select('code name nameEn nameZh color icon deeplink packageName')
    .sort({ name: 1 });

    res.json({
      success: true,
      bankServices: bankServices.map(bank => ({
        code: bank.code,
        name: bank.name,
        nameEn: bank.nameEn,
        nameZh: bank.nameZh,
        color: bank.color,
        icon: bank.icon,
        deeplink: bank.deeplink,
        packageName: bank.packageName
      }))
    });

  } catch (error) {
    console.error('❌ Get bank services error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch bank services'
    });
  }
});

// 💳 Launch Bank Service
app.post('/api/bank/launch', authenticateToken, [
  body('bankCode')
    .notEmpty()
    .withMessage('Bank code is required'),
  body('serviceType')
    .isIn(['scan_pay', 'transfer', 'topup', 'withdraw'])
    .withMessage('Service type must be scan_pay, transfer, topup, or withdraw')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        error: errors.array()[0].msg
      });
    }

    const { bankCode, serviceType } = req.body;

    console.log('💳 Launching bank service:', { bankCode, serviceType, userId: req.user._id });

    const identityVerification = await IdentityVerification.findOne({ 
      userId: req.user._id,
      status: 'verified'
    });

    if (!identityVerification) {
      return res.status(403).json({
        success: false,
        error: 'Identity verification required to use bank services'
      });
    }

    const bankService = await BankService.findOne({ 
      code: bankCode,
      isActive: true 
    });

    if (!bankService) {
      return res.status(404).json({
        success: false,
        error: 'Bank service not found'
      });
    }

    const deeplinkUrl = bankService.deeplink[serviceType];
    if (!deeplinkUrl) {
      return res.status(400).json({
        success: false,
        error: 'Service not available for this bank'
      });
    }

    const transaction = new Transaction({
      userId: req.user._id,
      walletId: (await Wallet.findOne({ userId: req.user._id }))._id,
      type: 'payment',
      amount: 0,
      currency: 'THB',
      description: `เริ่มใช้งานบริการ ${bankService.name} - ${serviceType}`,
      status: 'completed',
      referenceId: `BANK_${bankCode}_${Date.now()}`,
      metadata: {
        bankCode: bankCode,
        serviceType: serviceType,
        bankName: bankService.name,
        deeplink: deeplinkUrl
      }
    });
    await transaction.save();

    // ✅ เพิ่มการแจ้งเตือนใช้บริการธนาคาร
    await createBankServiceNotification(req.user._id, {
      bankName: bankService.name,
      serviceType: serviceType,
      deeplinkUrl: deeplinkUrl
    });

    console.log('✅ Bank service launched successfully:', {
      bankCode,
      serviceType,
      deeplinkUrl
    });

    res.json({
      success: true,
      message: 'Bank service launched successfully',
      bankService: {
        code: bankService.code,
        name: bankService.name,
        serviceType: serviceType,
        deeplinkUrl: deeplinkUrl,
        packageName: bankService.packageName
      },
      transactionId: transaction._id
    });

  } catch (error) {
    console.error('❌ Launch bank service error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to launch bank service'
    });
  }
});

// =============================================
// 🔐 AUTHENTICATION & PROFILE API ROUTES
// =============================================

// 👤 User Registration
app.post('/api/register', validateRegistration, async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        error: errors.array()[0].msg
      });
    }

    const { 
      username, 
      email, 
      password, 
      phone,
      language = 'en', 
      theme = 'white',
      pdpa_consent,
      consent_timestamp
    } = req.body;

    console.log('👤 User registration attempt:', { 
      username, 
      email, 
      phone,
      pdpa_consent,
      consent_timestamp 
    });

    if (!pdpa_consent) {
      return res.status(400).json({
        success: false,
        error: 'PDPA consent is required for registration'
      });
    }

    const existingUser = await User.findOne({ email });
    if (!existingUser) {
      const salt = generateSalt();
      const passwordHash = hashPassword(password, salt);
      const authToken = generateAuthToken(new mongoose.Types.ObjectId());

      const newUser = new User({
        username: username.trim(),
        email: email.trim().toLowerCase(),
        phone: phone ? phone.trim() : '',
        passwordHash,
        passwordSalt: salt,
        authToken,
        tokenExpiry: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
        settings: { 
          language: language,
          theme: theme
        },
        pdpaConsent: pdpa_consent,
        consentTimestamp: consent_timestamp || new Date().toISOString()
      });

      await newUser.save();

      await createUserWallet(newUser._id);

      await createOfficialChat(newUser._id);

      console.log('✅ User registered successfully with PDPA consent:', newUser._id);

      res.status(201).json({
        success: true,
        message: 'User registered successfully',
        user: {
          id: newUser._id,
          username: newUser.username,
          email: newUser.email,
          phone: newUser.phone,
          settings: newUser.settings,
          pdpaConsent: newUser.pdpaConsent,
          consentTimestamp: newUser.consentTimestamp
        },
        authToken
      });
    } else {
      return res.status(400).json({
        success: false,
        error: 'Email already registered'
      });
    }

  } catch (error) {
    console.error('❌ Registration error:', error);
    res.status(500).json({
      success: false,
      error: 'Registration failed: ' + error.message
    });
  }
});

// 🔐 User Login
app.post('/api/login', validateLogin, async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        error: errors.array()[0].msg
      });
    }

    const { email, password } = req.body;

    console.log('🔐 Login attempt for email:', email);

    const user = await User.findOne({ email: email.trim().toLowerCase() });
    if (user) {
      if (user.failedLoginAttempts >= 5) {
        const lockoutTime = 15 * 60 * 1000;
        const timeSinceLastAttempt = Date.now() - (user.lastLogin?.getTime() || 0);
        
        if (timeSinceLastAttempt < lockoutTime) {
          return res.status(429).json({
            success: false,
            error: 'Account temporarily locked due to too many failed attempts'
          });
        } else {
          user.failedLoginAttempts = 0;
        }
      }

      const isValid = verifyPassword(password, user.passwordHash, user.passwordSalt);
      if (isValid) {
        const authToken = generateAuthToken(user._id);
        
        user.authToken = authToken;
        user.tokenExpiry = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
        user.lastLogin = new Date();
        user.failedLoginAttempts = 0;
        await user.save();

        await createOfficialChat(user._id);

        console.log('✅ Login successful for user:', user._id);

        res.json({
          success: true,
          message: 'Login successful',
          user: {
            id: user._id,
            username: user.username,
            email: user.email,
            phone: user.phone,
            settings: user.settings,
            profilePicture: user.profilePicture,
            userId: user.userId,
            pdpaConsent: user.pdpaConsent
          },
          authToken
        });
      } else {
        user.failedLoginAttempts += 1;
        user.lastLogin = new Date();
        await user.save();
        
        console.log('❌ Invalid password for user:', email);
        return res.status(400).json({
          success: false,
          error: 'Invalid email or password'
        });
      }
    } else {
      console.log('❌ User not found:', email);
      return res.status(400).json({
        success: false,
        error: 'Invalid email or password'
      });
    }

  } catch (error) {
    console.error('❌ Login error:', error);
    res.status(500).json({
      success: false,
      error: 'Login failed'
    });
  }
});

// 👤 Get User Profile
app.get('/api/profile', authenticateToken, async (req, res) => {
  try {
    console.log('📋 Profile request for user:', req.user._id);
    
    const wallet = await Wallet.findOne({ userId: req.user._id });
    const identityVerification = await IdentityVerification.findOne({ userId: req.user._id });
    
    res.json({
      success: true,
      user: {
        id: req.user._id,
        username: req.user.username,
        email: req.user.email,
        phone: req.user.phone,
        settings: req.user.settings,
        profilePicture: req.user.profilePicture,
        userId: req.user.userId,
        lastLogin: req.user.lastLogin,
        pdpaConsent: req.user.pdpaConsent,
        consentTimestamp: req.user.consentTimestamp
      },
      wallet: wallet ? {
        balance: wallet.balance,
        coinPoints: wallet.coinPoints,
        currency: wallet.currency
      } : null,
      identityVerification: identityVerification ? {
        status: identityVerification.status,
        verificationMethod: identityVerification.verificationMethod,
        verifiedAt: identityVerification.verifiedAt
      } : null
    });
  } catch (error) {
    console.error('❌ Profile error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to get profile'
    });
  }
});

// 👤 Update User Profile
app.put('/api/profile', authenticateToken, [
  body('username')
    .isLength({ min: 3, max: 30 })
    .withMessage('Username must be between 3-30 characters')
    .trim()
    .escape(),
  body('phone')
    .optional()
    .isLength({ min: 10, max: 15 })
    .withMessage('Phone number must be between 10-15 characters')
    .matches(/^[0-9]+$/)
    .withMessage('Phone number must contain only numbers')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        error: errors.array()[0].msg
      });
    }

    const { username, profilePicture, phone } = req.body;

    console.log('👤 Updating profile for user:', req.user._id);

    if (username !== req.user.username) {
      const existingUser = await User.findOne({ 
        _id: { $ne: req.user._id },
        username: username.trim()
      });

      if (!existingUser) {
        req.user.username = username.trim();
        
        if (profilePicture) {
          req.user.profilePicture = profilePicture;
        }

        if (phone) {
          req.user.phone = phone.trim();
        }
        
        req.user.updatedAt = new Date();

        await req.user.save();

        // ✅ สร้างการแจ้งเตือนอัปเดตโปรไฟล์
        await createProfileUpdateNotification(req.user._id, {
          field: 'username',
          oldValue: req.user.username,
          newValue: username
        });

        console.log('✅ Profile updated successfully');

        res.json({
          success: true,
          message: 'Profile updated successfully',
          user: {
            id: req.user._id,
            username: req.user.username,
            email: req.user.email,
            phone: req.user.phone,
            profilePicture: req.user.profilePicture,
            settings: req.user.settings
          }
        });
      } else {
        return res.status(400).json({
          success: false,
          error: 'Username already taken'
        });
      }
    } else {
      if (profilePicture) {
        req.user.profilePicture = profilePicture;
        
        // ✅ สร้างการแจ้งเตือนอัปเดตโปรไฟล์
        await createProfileUpdateNotification(req.user._id, {
          field: 'profilePicture',
          oldValue: 'รูปเก่า',
          newValue: 'รูปใหม่'
        });
      }

      if (phone) {
        req.user.phone = phone.trim();
        
        // ✅ สร้างการแจ้งเตือนอัปเดตโปรไฟล์
        await createProfileUpdateNotification(req.user._id, {
          field: 'phone',
          oldValue: req.user.phone || 'ไม่ได้ตั้งค่า',
          newValue: phone
        });
      }

      req.user.updatedAt = new Date();
      await req.user.save();

      console.log('✅ Profile updated successfully');

      res.json({
        success: true,
        message: 'Profile updated successfully',
        user: {
          id: req.user._id,
          username: req.user.username,
          email: req.user.email,
          phone: req.user.phone,
          profilePicture: req.user.profilePicture,
          settings: req.user.settings
        }
      });
    }

  } catch (error) {
    console.error('❌ Update profile error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to update profile'
    });
  }
});

// =============================================
// 🔐 RECOVERY ID API ROUTES
// =============================================

// 🔑 Create Recovery ID
app.post('/api/recovery/create', authenticateToken, [
  body('securityQuestion')
    .isLength({ min: 5, max: 200 })
    .withMessage('Security question must be between 5-200 characters'),
  body('securityAnswer')
    .isLength({ min: 2, max: 100 })
    .withMessage('Security answer must be between 2-100 characters')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        error: errors.array()[0].msg
      });
    }

    const { securityQuestion, securityAnswer } = req.body;
    const userId = req.user._id;

    console.log('🔑 Creating recovery ID for user:', userId);

    const existingRecovery = await RecoveryId.findOne({ 
      userId: userId, 
      isActive: true 
    });

    if (existingRecovery) {
      return res.status(400).json({
        success: false,
        error: 'Recovery ID already exists for this account'
      });
    }

    const recoveryId = generateRecoveryId();
    const hashedAnswer = hashPassword(securityAnswer.toLowerCase().trim(), req.user.passwordSalt);

    const newRecovery = new RecoveryId({
      userId: userId,
      recoveryId: recoveryId,
      securityQuestion: securityQuestion.trim(),
      securityAnswer: hashedAnswer,
      isActive: true
    });

    await newRecovery.save();

    await sendRecoveryEmail(req.user.email, recoveryId, securityQuestion);

    console.log('✅ Recovery ID created successfully:', recoveryId);

    res.json({
      success: true,
      message: 'Recovery ID created successfully',
      recoveryId: recoveryId,
      securityQuestion: securityQuestion
    });

  } catch (error) {
    console.error('❌ Create recovery ID error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to create recovery ID'
    });
  }
});

// 🔍 Get Recovery ID Info
app.get('/api/recovery/info', authenticateToken, async (req, res) => {
  try {
    const userId = req.user._id;

    console.log('🔍 Getting recovery info for user:', userId);

    const recoveryInfo = await RecoveryId.findOne({ 
      userId: userId, 
      isActive: true 
    }).select('recoveryId securityQuestion createdAt');

    if (recoveryInfo) {
      res.json({
        success: true,
        hasRecoveryId: true,
        recoveryId: recoveryInfo.recoveryId,
        securityQuestion: recoveryInfo.securityQuestion,
        createdAt: recoveryInfo.createdAt
      });
    } else {
      res.json({
        success: true,
        hasRecoveryId: false,
        message: 'No recovery ID set up for this account'
      });
    }

  } catch (error) {
    console.error('❌ Get recovery info error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to get recovery info'
    });
  }
});

// 🔄 Update Recovery ID
app.put('/api/recovery/update', authenticateToken, [
  body('currentAnswer')
    .notEmpty()
    .withMessage('Current security answer is required'),
  body('newSecurityQuestion')
    .isLength({ min: 5, max: 200 })
    .withMessage('New security question must be between 5-200 characters'),
  body('newSecurityAnswer')
    .isLength({ min: 2, max: 100 })
    .withMessage('New security answer must be between 2-100 characters')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        error: errors.array()[0].msg
      });
    }

    const { currentAnswer, newSecurityQuestion, newSecurityAnswer } = req.body;
    const userId = req.user._id;

    console.log('🔄 Updating recovery ID for user:', userId);

    const recoveryInfo = await RecoveryId.findOne({ 
      userId: userId, 
      isActive: true 
    });

    if (!recoveryInfo) {
      return res.status(404).json({
        success: false,
        error: 'Recovery ID not found'
      });
    }

    const isCurrentAnswerValid = verifyPassword(
      currentAnswer.toLowerCase().trim(), 
      recoveryInfo.securityAnswer, 
      req.user.passwordSalt
    );

    if (!isCurrentAnswerValid) {
      return res.status(400).json({
        success: false,
        error: 'Current security answer is incorrect'
      });
    }

    recoveryInfo.securityQuestion = newSecurityQuestion.trim();
    recoveryInfo.securityAnswer = hashPassword(newSecurityAnswer.toLowerCase().trim(), req.user.passwordSalt);
    recoveryInfo.updatedAt = new Date();

    await recoveryInfo.save();

    console.log('✅ Recovery ID updated successfully');

    res.json({
      success: true,
      message: 'Recovery ID updated successfully',
      recoveryId: recoveryInfo.recoveryId,
      securityQuestion: newSecurityQuestion
    });

  } catch (error) {
    console.error('❌ Update recovery ID error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to update recovery ID'
    });
  }
});

// 🗑️ Delete Recovery ID
app.delete('/api/recovery/delete', authenticateToken, [
  body('securityAnswer')
    .notEmpty()
    .withMessage('Security answer is required')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        error: errors.array()[0].msg
      });
    }

    const { securityAnswer } = req.body;
    const userId = req.user._id;

    console.log('🗑️ Deleting recovery ID for user:', userId);

    const recoveryInfo = await RecoveryId.findOne({ 
      userId: userId, 
      isActive: true 
    });

    if (!recoveryInfo) {
      return res.status(404).json({
        success: false,
        error: 'Recovery ID not found'
      });
    }

    const isAnswerValid = verifyPassword(
      securityAnswer.toLowerCase().trim(), 
      recoveryInfo.securityAnswer, 
      req.user.passwordSalt
    );

    if (!isAnswerValid) {
      return res.status(400).json({
        success: false,
        error: 'Security answer is incorrect'
      });
    }

    recoveryInfo.isActive = false;
    recoveryInfo.updatedAt = new Date();

    await recoveryInfo.save();

    console.log('✅ Recovery ID deleted successfully');

    res.json({
      success: true,
      message: 'Recovery ID deleted successfully'
    });

  } catch (error) {
    console.error('❌ Delete recovery ID error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to delete recovery ID'
    });
  }
});

// 🔓 Recover Account with Recovery ID
app.post('/api/recovery/account', [
  body('recoveryId')
    .notEmpty()
    .withMessage('Recovery ID is required'),
  body('securityAnswer')
    .notEmpty()
    .withMessage('Security answer is required'),
  body('newPassword')
    .isLength({ min: 6 })
    .withMessage('New password must be at least 6 characters')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        error: errors.array()[0].msg
      });
    }

    const { recoveryId, securityAnswer, newPassword } = req.body;

    console.log('🔓 Account recovery attempt with ID:', recoveryId);

    const recoveryInfo = await RecoveryId.findOne({ 
      recoveryId: recoveryId.toUpperCase().trim(),
      isActive: true 
    }).populate('userId');

    if (!recoveryInfo || !recoveryInfo.userId) {
      return res.status(404).json({
        success: false,
        error: 'Invalid recovery ID or account not found'
      });
    }

    const user = recoveryInfo.userId;

    const isAnswerValid = verifyPassword(
      securityAnswer.toLowerCase().trim(), 
      recoveryInfo.securityAnswer, 
      user.passwordSalt
    );

    if (!isAnswerValid) {
      return res.status(400).json({
        success: false,
        error: 'Security answer is incorrect'
      });
    }

    user.passwordHash = hashPassword(newPassword, user.passwordSalt);
    user.updatedAt = new Date();

    await user.save();

    console.log('✅ Account recovered successfully for user:', user._id);

    res.json({
      success: true,
      message: 'Password reset successfully. You can now login with your new password.',
      username: user.username,
      email: user.email
    });

  } catch (error) {
    console.error('❌ Account recovery error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to recover account'
    });
  }
});

// 🔍 Verify Recovery ID
app.post('/api/recovery/verify', [
  body('recoveryId')
    .notEmpty()
    .withMessage('Recovery ID is required')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        error: errors.array()[0].msg
      });
    }

    const { recoveryId } = req.body;

    console.log('🔍 Verifying recovery ID:', recoveryId);

    const recoveryInfo = await RecoveryId.findOne({ 
      recoveryId: recoveryId.toUpperCase().trim(),
      isActive: true 
    }).populate('userId', 'username email');

    if (!recoveryInfo || !recoveryInfo.userId) {
      return res.status(404).json({
        success: false,
        error: 'Invalid recovery ID'
      });
    }

    res.json({
      success: true,
      securityQuestion: recoveryInfo.securityQuestion,
      userHint: recoveryInfo.userId.username
    });

  } catch (error) {
    console.error('❌ Verify recovery ID error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to verify recovery ID'
    });
  }
});

// 🔍 Verify Security Answer
app.post('/api/recovery/verify-answer', [
  body('recoveryId')
    .notEmpty()
    .withMessage('Recovery ID is required'),
  body('securityAnswer')
    .notEmpty()
    .withMessage('Security answer is required')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        error: errors.array()[0].msg
      });
    }

    const { recoveryId, securityAnswer } = req.body;

    console.log('🔍 Verifying security answer for recovery ID:', recoveryId);

    const recoveryInfo = await RecoveryId.findOne({ 
      recoveryId: recoveryId.toUpperCase().trim(),
      isActive: true 
    }).populate('userId');

    if (!recoveryInfo || !recoveryInfo.userId) {
      return res.status(404).json({
        success: false,
        error: 'Invalid recovery ID'
      });
    }

    const user = recoveryInfo.userId;

    const isAnswerValid = verifyPassword(
      securityAnswer.toLowerCase().trim(), 
      recoveryInfo.securityAnswer, 
      user.passwordSalt
    );

    if (!isAnswerValid) {
      return res.status(400).json({
        success: false,
        error: 'Security answer is incorrect'
      });
    }

    console.log('✅ Security answer verified successfully for user:', user._id);

    res.json({
      success: true,
      message: 'Security answer verified successfully',
      verified: true,
      username: user.username
    });

  } catch (error) {
    console.error('❌ Verify security answer error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to verify security answer'
    });
  }
});

// =============================================
// 💬 CHAT SYSTEM API ROUTES
// =============================================

// 👤 Get Contact Profile Picture for Chat
app.get('/api/chats/:chatId/profile', authenticateToken, async (req, res) => {
  try {
    const { chatId } = req.params;
    
    console.log('📸 Fetching contact profile for chat:', chatId);

    const chat = await Chat.findOne({
      _id: chatId,
      participants: req.user._id,
      isActive: true
    })
    .populate('participants', 'username email userType profilePicture userId phone');

    if (!chat) {
      return res.status(404).json({
        success: false,
        error: 'Chat not found'
      });
    }

    const contactUser = chat.participants.find(
      participant => participant._id.toString() !== req.user._id.toString()
    );

    if (!contactUser) {
      return res.status(404).json({
        success: false,
        error: 'Contact not found'
      });
    }

    console.log('✅ Found contact profile:', {
      contactId: contactUser._id,
      username: contactUser.username,
      hasProfilePicture: !!contactUser.profilePicture
    });

    res.json({
      success: true,
      profilePicture: contactUser.profilePicture || '',
      contactInfo: {
        id: contactUser.userId || contactUser._id.toString(),
        username: contactUser.username,
        email: contactUser.email,
        userType: contactUser.userType,
        phone: contactUser.phone
      }
    });

  } catch (error) {
    console.error('❌ Get contact profile error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch contact profile'
    });
  }
});

// 👤 Get My Profile Picture
app.get('/api/profile/picture', authenticateToken, async (req, res) => {
  try {
    console.log('📸 Fetching my profile picture for user:', req.user._id);

    res.json({
      success: true,
      profilePicture: req.user.profilePicture || '',
      userInfo: {
        id: req.user.userId || req.user._id.toString(),
        username: req.user.username,
        email: req.user.email,
        phone: req.user.phone
      }
    });

  } catch (error) {
    console.error('❌ Get my profile picture error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch profile picture'
    });
  }
});

// 💬 Create New Chat
app.post('/api/chats', authenticateToken, async (req, res) => {
  try {
    const { participants, isGroup, name, avatar, backgroundColor } = req.body; // ✅ รับค่าเพิ่ม
    const userId = req.user._id;

    console.log('💬 Creating new chat request:', { 
      userId: userId,
      participants: participants,
      isGroup: isGroup,
      name: name
    });

    if (!participants || !Array.isArray(participants) || participants.length === 0) {
      return res.status(400).json({ success: false, error: 'Participants array is required' });
    }

    // แปลง ID เป็น ObjectId
    const users = await User.find({ 
      $or: [
        { userId: { $in: participants } },
        { _id: { $in: participants.filter(id => mongoose.Types.ObjectId.isValid(id)) } }
      ]
    }, 'userId _id username name email profilePicture phone');

    const participantIds = users.map(user => user._id);
    const allParticipants = [userId, ...participantIds];
    const uniqueParticipants = [...new Set(allParticipants.map(id => id.toString()))].map(id => new mongoose.Types.ObjectId(id));

    // ถ้าเป็นแชทเดี่ยว ให้เช็คว่ามีอยู่แล้วไหม
    if (!isGroup) {
      const existingChat = await Chat.findOne({
        participants: { $all: uniqueParticipants },
        chatType: 'direct',
        $expr: { $eq: [{ $size: "$participants" }, uniqueParticipants.length] }
      }).populate('participants', 'userId username name email profilePicture phone');

      if (existingChat) {
        return res.json({ success: true, chat: { id: existingChat._id, ...existingChat.toObject() }, message: 'Chat already exists' });
      }
    }

    // ตั้งชื่อแชท
    let chatTitle = name;
    if (!chatTitle) {
      const otherUsers = users.filter(user => user._id.toString() !== userId.toString());
      chatTitle = otherUsers.map(user => user.username).join(', ');
    }

    // ✅ สร้างแชทใหม่ (รองรับกลุ่ม)
    const newChat = new Chat({
      participants: uniqueParticipants,
      chatType: isGroup ? 'group' : 'direct', // ✅ กำหนดประเภท
      title: chatTitle,
      lastMessage: isGroup ? 'สร้างกลุ่มแล้ว' : 'เริ่มการสนทนา',
      lastMessageTime: new Date(),
      createdBy: userId,
      // ถ้าคุณมี field สำหรับ avatar หรือ color ใน Schema ให้ใส่ตรงนี้
      // avatar: avatar, 
      // backgroundColor: backgroundColor
    });

    await newChat.save();
    await newChat.populate('participants', 'userId username name email profilePicture phone');

    // สร้างข้อความต้อนรับ
    const welcomeMessage = new Message({
      chatId: newChat._id,
      senderId: userId,
      messageType: 'system',
      content: isGroup ? `สร้างกลุ่ม "${chatTitle}" แล้ว` : 'เริ่มการสนทนา',
      timestamp: new Date()
    });
    await welcomeMessage.save();

    res.json({
      success: true,
      chat: {
        id: newChat._id,
        _id: newChat._id,
        participants: newChat.participants,
        chatType: newChat.chatType,
        isGroup: newChat.chatType === 'group', // ✅ ส่ง flag กลับไป
        title: newChat.title,
        lastMessage: newChat.lastMessage,
        lastMessageTime: newChat.lastMessageTime
      },
      message: 'Chat created successfully'
    });

  } catch (error) {
    console.error('❌ Error creating chat:', error);
    res.status(500).json({ success: false, error: 'Failed to create chat: ' + error.message });
  }
});

// 💬 Get Private Chat with Friend
app.get('/api/chats/private/:friendId', authenticateToken, async (req, res) => {
  try {
    const { friendId } = req.params;
    const userId = req.user._id;

    console.log('🔍 Finding private chat with friend:', { 
      userId: userId,
      friendId: friendId 
    });

    const friendUser = await User.findOne({
      $or: [
        { userId: friendId },
        { _id: friendId }
      ]
    });

    if (!friendUser) {
      return res.status(404).json({
        success: false,
        error: 'Friend not found'
      });
    }

    const chat = await Chat.findOne({
      participants: { $all: [userId, friendUser._id] },
      chatType: 'direct'
    }).populate('participants', 'userId username name email profilePicture phone');

    if (chat) {
      console.log('✅ Found existing private chat:', chat._id);
      res.json({
        success: true,
        chat: {
          id: chat._id,
          _id: chat._id,
          participants: chat.participants,
          chatType: chat.chatType,
          title: chat.title,
          createdAt: chat.createdAt,
          lastMessage: chat.lastMessage,
          lastMessageTime: chat.lastMessageTime
        },
        exists: true
      });
    } else {
      console.log('📝 No existing private chat found');
      res.json({
        success: true,
        chat: null,
        exists: false
      });
    }

  } catch (error) {
    console.error('❌ Error finding private chat:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to find private chat: ' + error.message
    });
  }
});

// 👥 Search Users
app.get('/api/users/search', authenticateToken, async (req, res) => {
  try {
    const { query } = req.query;

    console.log('🔍 User search request:', {
      userId: req.user._id,
      query: query
    });

    if (!query || typeof query !== 'string' || query.trim().length < 2) {
      return res.status(400).json({
        success: false,
        error: 'Search query must be at least 2 characters'
      });
    }

    const searchTerm = escapeRegex(query.trim());

    const users = await User.find({
      _id: { $ne: req.user._id },
      $or: [
        { username: { $regex: searchTerm, $options: 'i' } },
        { email: { $regex: searchTerm, $options: 'i' } },
        { userId: { $regex: searchTerm, $options: 'i' } },
        { phone: { $regex: searchTerm, $options: 'i' } }
      ],
      isActive: true
    })
    .select('username email userId profilePicture userType lastLogin createdAt phone')
    .limit(20);

    console.log('✅ Found', users.length, 'users for query:', searchTerm);

    const formattedUsers = users.map(user => ({
      id: user.userId || user._id.toString(),
      name: user.username,
      email: user.email,
      phone: user.phone,
      avatar: user.profilePicture || '👤',
      isOnline: user.lastLogin && (Date.now() - user.lastLogin.getTime() < 5 * 60 * 1000),
      mutualFriends: 0,
      userType: user.userType
    }));

    res.json({
      success: true,
      users: formattedUsers,
      count: formattedUsers.length
    });

  } catch (error) {
    console.error('❌ User search error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to search users'
    });
  }
});

// 👥 Send Friend Request
app.post('/api/friends/request', authenticateToken, async (req, res) => {
  try {
    const { targetUserId } = req.body;

    console.log('👥 Friend request received:', {
      fromUserId: req.user.userId,
      fromUserMongoId: req.user._id,
      fromUsername: req.user.username,
      targetUserId: targetUserId
    });

    if (!targetUserId) {
      console.log('❌ Target user ID is required');
      return res.status(400).json({
        success: false,
        error: 'Target user ID is required'
      });
    }

    let targetUser = await User.findOne({ 
      userId: targetUserId,
      isActive: true 
    });
    
    if (!targetUser && mongoose.Types.ObjectId.isValid(targetUserId)) {
      targetUser = await User.findOne({ 
        _id: targetUserId,
        isActive: true 
      });
    }

    if (!targetUser) {
      console.log('❌ Target user not found:', targetUserId);
      return res.status(404).json({
        success: false,
        error: 'User not found'
      });
    }

    console.log('✅ Target user found:', {
      targetUserId: targetUser.userId,
      targetMongoId: targetUser._id,
      username: targetUser.username
    });

    if (targetUser._id.toString() === req.user._id.toString()) {
      console.log('❌ Cannot send friend request to yourself');
      return res.status(400).json({
        success: false,
        error: 'Cannot send friend request to yourself'
      });
    }

    const existingRequest = await FriendRequest.findOne({
      fromUser: req.user._id,
      toUser: targetUser._id,
      status: 'pending'
    });

    if (existingRequest) {
      console.log('❌ Friend request already sent');
      return res.status(400).json({
        success: false,
        error: 'Friend request already sent'
      });
    }

    const existingFriendship = await FriendRequest.findOne({
      $or: [
        { fromUser: req.user._id, toUser: targetUser._id, status: 'accepted' },
        { fromUser: targetUser._id, toUser: req.user._id, status: 'accepted' }
      ]
    });

    if (existingFriendship) {
      console.log('❌ Users are already friends');
      return res.status(400).json({
        success: false,
        error: 'You are already friends with this user'
      });
    }

    const friendRequest = new FriendRequest({
      fromUser: req.user._id,
      toUser: targetUser._id,
      status: 'pending'
    });

    await friendRequest.save();
    console.log('✅ Friend request saved successfully:', friendRequest._id);

    // ✅ สร้างการแจ้งเตือนคำขอเป็นเพื่อน
    await createFriendRequestNotification(targetUser._id, {
      requesterName: req.user.username,
      requesterId: req.user.userId
    });

    res.json({
      success: true,
      message: 'Friend request sent successfully',
      targetUser: {
        id: targetUser.userId || targetUser._id.toString(),
        name: targetUser.username,
        email: targetUser.email,
        phone: targetUser.phone
      },
      requestId: friendRequest._id
    });

  } catch (error) {
    console.error('❌ Send friend request error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to send friend request: ' + error.message
    });
  }
});

// 👥 Get User Profile by ID
app.get('/api/users/:userId', authenticateToken, async (req, res) => {
  try {
    const { userId } = req.params;

    console.log('📋 Get user profile:', userId);

    const user = await User.findOne({
      $or: [
        { userId: userId },
        { _id: userId }
      ],
      isActive: true
    })
    .select('username email userId profilePicture userType lastLogin createdAt phone');

    if (!user) {
      return res.status(404).json({
        success: false,
        error: 'User not found'
      });
    }

    const userProfile = {
      id: user.userId || user._id.toString(),
      name: user.username,
      email: user.email,
      phone: user.phone,
      avatar: user.profilePicture || '👤',
      isOnline: user.lastLogin && (Date.now() - user.lastLogin.getTime() < 5 * 60 * 1000),
      mutualFriends: 0,
      userType: user.userType,
      joinDate: user.createdAt
    };

    console.log('✅ User profile found:', userProfile.name);

    res.json({
      success: true,
      user: userProfile
    });

  } catch (error) {
    console.error('❌ Get user profile error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to get user profile'
    });
  }
});

// 📩 Get Friend Requests
app.get('/api/friends/requests', authenticateToken, async (req, res) => {
  try {
    console.log('📩 Getting friend requests for user:', req.user._id);

    const friendRequests = await FriendRequest.find({
      toUser: req.user._id,
      status: 'pending'
    })
    .populate('fromUser', 'username email userId profilePicture userType lastLogin phone')
    .sort({ createdAt: -1 });

    const formattedRequests = friendRequests.map(request => ({
      id: request._id,
      sender: {
        id: request.fromUser.userId || request.fromUser._id.toString(),
        name: request.fromUser.username,
        email: request.fromUser.email,
        phone: request.fromUser.phone,
        avatar: request.fromUser.profilePicture || '👤',
        isOnline: request.fromUser.lastLogin && (Date.now() - request.fromUser.lastLogin.getTime() < 5 * 60 * 1000),
        userType: request.fromUser.userType
      },
      status: request.status,
      createdAt: request.createdAt
    }));

    console.log('✅ Found', formattedRequests.length, 'friend requests');

    res.json({
      success: true,
      requests: formattedRequests,
      count: formattedRequests.length
    });

  } catch (error) {
    console.error('❌ Get friend requests error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to get friend requests'
    });
  }
});

// 👫 Get Friends List
app.get('/api/friends', authenticateToken, async (req, res) => {
  try {
    console.log('👫 Getting friends list for user:', req.user._id);

    const friendRequests = await FriendRequest.find({
      $or: [
        { fromUser: req.user._id, status: 'accepted' },
        { toUser: req.user._id, status: 'accepted' }
      ]
    })
    .populate('fromUser', 'username email userId profilePicture userType lastLogin createdAt phone')
    .populate('toUser', 'username email userId profilePicture userType lastLogin createdAt phone')
    .sort({ updatedAt: -1 });

    const friends = friendRequests.map(request => {
      const isFromUser = request.fromUser._id.toString() === req.user._id.toString();
      const friendUser = isFromUser ? request.toUser : request.fromUser;
      
      return {
        id: friendUser.userId || friendUser._id.toString(),
        name: friendUser.username,
        email: friendUser.email,
        phone: friendUser.phone,
        avatar: friendUser.profilePicture || '👤',
        isOnline: friendUser.lastLogin && (Date.now() - friendUser.lastLogin.getTime() < 5 * 60 * 1000),
        userType: friendUser.userType,
        friendshipDate: request.updatedAt,
        mutualFriends: 0
      };
    });

    console.log('✅ Found', friends.length, 'friends');

    res.json({
      success: true,
      friends: friends,
      count: friends.length
    });

  } catch (error) {
    console.error('❌ Get friends error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to get friends list'
    });
  }
});

// ✅ Accept Friend Request
app.post('/api/friends/requests/:requestId/accept', authenticateToken, async (req, res) => {
  try {
    const { requestId } = req.params;

    console.log('✅ Accepting friend request:', requestId);

    const friendRequest = await FriendRequest.findOne({
      _id: requestId,
      toUser: req.user._id,
      status: 'pending'
    })
    .populate('fromUser', 'username email userId phone')
    .populate('toUser', 'username email userId phone');

    if (!friendRequest) {
      return res.status(404).json({
        success: false,
        error: 'Friend request not found or already processed'
      });
    }

    friendRequest.status = 'accepted';
    friendRequest.updatedAt = new Date();
    await friendRequest.save();

    console.log('✅ Friend request accepted successfully');

    // ✅ สร้างการแจ้งเตือนยอมรับเพื่อน
    await createFriendAcceptNotification(friendRequest.fromUser, {
      friendName: req.user.username,
      friendId: req.user.userId
    });

    res.json({
      success: true,
      message: 'Friend request accepted successfully',
      friend: {
        id: friendRequest.fromUser.userId || friendRequest.fromUser._id.toString(),
        name: friendRequest.fromUser.username,
        email: friendRequest.fromUser.email,
        phone: friendRequest.fromUser.phone
      },
      requestId: friendRequest._id
    });

  } catch (error) {
    console.error('❌ Accept friend request error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to accept friend request'
    });
  }
});

// ❌ Reject Friend Request
app.post('/api/friends/requests/:requestId/reject', authenticateToken, async (req, res) => {
  try {
    const { requestId } = req.params;

    console.log('❌ Rejecting friend request:', requestId);

    const friendRequest = await FriendRequest.findOne({
      _id: requestId,
      toUser: req.user._id,
      status: 'pending'
    })
    .populate('fromUser', 'username email userId phone');

    if (!friendRequest) {
      return res.status(404).json({
        success: false,
        error: 'Friend request not found or already processed'
      });
    }

    friendRequest.status = 'rejected';
    friendRequest.updatedAt = new Date();
    await friendRequest.save();

    console.log('✅ Friend request rejected successfully');

    res.json({
      success: true,
      message: 'Friend request rejected successfully',
      requestId: friendRequest._id
    });

  } catch (error) {
    console.error('❌ Reject friend request error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to reject friend request'
    });
  }
});

// 🗑️ Remove Friend
app.delete('/api/friends/:friendId', authenticateToken, async (req, res) => {
  try {
    const { friendId } = req.params;

    console.log('🗑️ Removing friend:', friendId, 'for user:', req.user._id);

    const friendUser = await User.findOne({
      $or: [
        { userId: friendId },
        { _id: friendId }
      ]
    });

    if (!friendUser) {
      return res.status(404).json({
        success: false,
        error: 'Friend not found'
      });
    }

    const deletedRequest = await FriendRequest.findOneAndDelete({
      $or: [
        { fromUser: req.user._id, toUser: friendUser._id, status: 'accepted' },
        { fromUser: friendUser._id, toUser: req.user._id, status: 'accepted' }
      ]
    });

    if (!deletedRequest) {
      return res.status(404).json({
        success: false,
        error: 'Friendship not found'
      });
    }

    console.log('✅ Friend removed successfully');

    res.json({
      success: true,
      message: 'Friend removed successfully',
      removedFriend: {
        id: friendUser.userId || friendUser._id.toString(),
        name: friendUser.username,
        phone: friendUser.phone
      }
    });

  } catch (error) {
    console.error('❌ Remove friend error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to remove friend'
    });
  }
});

// 🔍 Check Friendship Status
app.get('/api/friends/status/:targetUserId', authenticateToken, async (req, res) => {
  try {
    const { targetUserId } = req.params;

    console.log('🔍 Checking friendship status with:', targetUserId);

    const targetUser = await User.findOne({
      $or: [
        { userId: targetUserId },
        { _id: targetUserId }
      ]
    });

    if (!targetUser) {
      return res.status(404).json({
        success: false,
        error: 'User not found'
      });
    }

    const friendRequest = await FriendRequest.findOne({
      $or: [
        { fromUser: req.user._id, toUser: targetUser._id },
        { fromUser: targetUser._id, toUser: req.user._id }
      ]
    });

    let status = 'not_friends';
    let requestId = null;

    if (friendRequest) {
      status = friendRequest.status;
      requestId = friendRequest._id;
    }

    console.log('✅ Friendship status:', status);

    res.json({
      success: true,
      status: status,
      requestId: requestId,
      targetUser: {
        id: targetUser.userId || targetUser._id.toString(),
        name: targetUser.username,
        phone: targetUser.phone
      }
    });

  } catch (error) {
    console.error('❌ Check friendship status error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to check friendship status'
    });
  }
});

// 💬 Get User Chats
app.get('/api/chats', authenticateToken, async (req, res) => {
  try {
    console.log('💬 Fetching chats for user:', req.user._id);

    const chats = await Chat.find({
      participants: req.user._id,
      isActive: true
    })
    .populate('participants', 'username email userType profilePicture userId phone')
    .sort({ lastMessageTime: -1 });

    const officialChats = chats.filter(chat => chat.chatType === 'official');
    const normalChats = chats.filter(chat => chat.chatType !== 'official');
    
    let finalChats = [...normalChats];
    
    if (officialChats.length > 0) {
      const sortedOfficialChats = officialChats.sort((a, b) => 
        new Date(b.lastMessageTime) - new Date(a.lastMessageTime)
      );
      finalChats.unshift(sortedOfficialChats[0]);
      
      if (officialChats.length > 1) {
        console.log(`🔥 Filtered official chats: 1 (was ${officialChats.length}) for user: ${req.user._id}`);
      }
    }

    const formattedChats = finalChats.map(chat => {
      // ✅ Logic การหาชื่อและรูปภาพที่ถูกต้อง
      let chatName = chat.title;
      let chatAvatar = chat.chatType === 'official' ? '💼' : (chat.chatType === 'group' ? '👥' : '👤');
      let otherParticipant = null;
      let profilePicture = null;

      // ถ้าเป็นแชทเดี่ยว ให้ใช้ชื่อเพื่อน
      if (chat.chatType === 'direct') {
        otherParticipant = chat.participants.find(
          p => p._id.toString() !== req.user._id.toString()
        );
        if (otherParticipant) {
          chatName = otherParticipant.username;
          profilePicture = otherParticipant.profilePicture;
        }
      } 
      // ถ้าเป็นกลุ่ม ให้ใช้ชื่อกลุ่ม (chat.title) ซึ่งถูกต้องแล้ว

      return {
        id: chat._id,
        name: chatName,
        lastMessage: chat.lastMessage,
        timestamp: chat.lastMessageTime,
        unreadCount: chat.unreadCount.get(req.user._id.toString()) || 0,
        isOnline: otherParticipant ? (otherParticipant.userType === 'system' ? true : false) : false,
        avatar: chatAvatar,
        chatType: chat.chatType,
        isOfficial: chat.chatType === 'official',
        isGroup: chat.chatType === 'group', // ✅ สำคัญ: ต้องส่งค่านี้เพื่อให้แอปแยกกลุ่มได้
        profilePicture: profilePicture,
        contactId: otherParticipant?.userId || otherParticipant?._id.toString(),
        phone: otherParticipant?.phone || null
      };
    });

    console.log('✅ Found', formattedChats.length, 'chats for user (official:', officialChats.length, 'normal:', normalChats.length + ')');

    res.json({
      success: true,
      chats: formattedChats
    });

  } catch (error) {
    console.error('❌ Get chats error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch chats'
    });
  }
});

// 🔔 Route: Send Chat Push Notification (Manual)
app.post('/api/chat/push-notification', authenticateToken, async (req, res) => {
  try {
    const { chatId, senderName, message, messageType = 'text' } = req.body;

    console.log('🔔 Manual push notification request:', { chatId, senderName });

    const chat = await Chat.findById(chatId).populate('participants');
    if (!chat) {
      return res.status(404).json({ success: false, error: 'Chat not found' });
    }

    // กำหนดหัวข้อและเนื้อหา
    let notificationTitle = senderName;
    let notificationBody = message;

    // ✅ ถ้าเป็นกลุ่ม ให้หัวข้อเป็นชื่อกลุ่ม
    if (chat.chatType === 'group') {
      notificationTitle = chat.title;
      notificationBody = `${senderName}: ${message}`;
    }

    // ส่งหาทุกคนในแชท ยกเว้นคนส่ง
    const recipients = chat.participants.filter(p => p._id.toString() !== req.user._id.toString());

    if (recipients.length === 0) {
      return res.json({ success: true, message: 'No recipients' });
    }

    // ส่ง Notification
    const promises = recipients.map(async (recipient) => {
      // เรียกใช้ฟังก์ชัน createNotification ที่มีอยู่แล้วในโค้ดของคุณ
      return createNotification({
        userId: recipient._id,
        type: 'chat_message',
        title: notificationTitle,
        message: notificationBody,
        icon: chat.chatType === 'group' ? '👥' : '💬',
        color: '#1FAE4B',
        data: {
          chatId: chatId.toString(),
          senderName,
          messageType,
          isGroup: chat.chatType === 'group',
          timestamp: new Date().toISOString()
        },
        priority: 'high',
        sourceId: `chat_push_${chatId}_${Date.now()}`
      });
    });

    await Promise.all(promises);

    res.json({ success: true, message: 'Notifications sent', count: recipients.length });

  } catch (error) {
    console.error('❌ Push notification error:', error);
    res.status(500).json({ success: false, error: 'Failed to send notification' });
  }
});

// 💬 Get Chat Messages
app.get('/api/chats/:chatId/messages', authenticateToken, async (req, res) => {
  try {
    const { chatId } = req.params;
    
    console.log('📨 Fetching messages for chat:', chatId);

    const chat = await Chat.findOne({
      _id: chatId,
      participants: req.user._id
    });

    if (chat) {
      const messages = await Message.find({ 
        chatId,
        isDeleted: false
      })
        .populate('senderId', 'username userType profilePicture userId phone')
        .sort({ timestamp: 1 });

      const formattedMessages = messages.map(msg => {
        const isMe = msg.senderId._id.toString() === req.user._id.toString();
        const isSystem = msg.senderId.userType === 'system';
        
        return {
          id: msg._id,
          sender: msg.senderId.username,
          message: msg.content,
          timestamp: msg.timestamp,
          isMe: isMe,
          isSystem: isSystem,
          messageType: msg.messageType,
          isDeleted: false,
          profilePicture: msg.senderId.profilePicture,
          senderId: msg.senderId.userId || msg.senderId._id.toString(),
          phone: msg.senderId.phone
        };
      });

      console.log('✅ Found', formattedMessages.length, 'messages for chat');

      res.json({
        success: true,
        messages: formattedMessages
      });
    } else {
      return res.status(404).json({
        success: false,
        error: 'Chat not found'
      });
    }

  } catch (error) {
    console.error('❌ Get messages error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch messages'
    });
  }
});

// 💬 Send Message
app.post('/api/chats/:chatId/messages', authenticateToken, async (req, res) => {
  try {
    const { chatId } = req.params;
    const { content, messageType = 'text' } = req.body;

    console.log('📤 Sending message to chat:', chatId);

    const chat = await Chat.findOne({
      _id: chatId,
      participants: req.user._id
    });

    if (chat) {
      const newMessage = new Message({
        chatId,
        senderId: req.user._id,
        messageType,
        content
      });

      await newMessage.save();

      chat.lastMessage = content;
      chat.lastMessageTime = new Date();
      
      chat.unreadCount.set(req.user._id.toString(), 0);
      
      chat.participants.forEach(participantId => {
        if (participantId.toString() !== req.user._id.toString()) {
          const currentCount = chat.unreadCount.get(participantId.toString()) || 0;
          chat.unreadCount.set(participantId.toString(), currentCount + 1);
        }
      });

      await chat.save();

      // ✅ สร้างการแจ้งเตือนข้อความใหม่สำหรับผู้ใช้คนอื่น
      chat.participants.forEach(async (participantId) => {
        if (participantId.toString() !== req.user._id.toString()) {
          const otherUser = await User.findById(participantId);
          if (otherUser) {
            await createChatMessageNotification(participantId, {
              senderName: req.user.username,
              message: content,
              chatId: chatId,
              messageType: messageType
            });
          }
        }
      });

      console.log('✅ Message sent successfully');

      res.json({
        success: true,
        message: {
          id: newMessage._id,
          sender: req.user.username,
          message: content,
          timestamp: newMessage.timestamp,
          isMe: true,
          isSystem: false,
          messageType,
          profilePicture: req.user.profilePicture,
          phone: req.user.phone
        }
      });
    } else {
      return res.status(404).json({
        success: false,
        error: 'Chat not found'
      });
    }

  } catch (error) {
    console.error('❌ Send message error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to send message'
    });
  }
});

// 🔥 Soft Delete Message
app.put('/api/chats/:chatId/messages/:messageId/delete', authenticateToken, async (req, res) => {
  try {
    const { chatId, messageId } = req.params;
    
    console.log('🗑️ Soft deleting message:', messageId, 'from chat:', chatId);

    const chat = await Chat.findOne({
      _id: chatId,
      participants: req.user._id
    });

    if (chat) {
      const message = await Message.findOne({
        _id: messageId,
        chatId: chatId
      });

      if (message) {
        if (message.senderId.toString() === req.user._id.toString()) {
          message.isDeleted = true;
          message.deletedAt = new Date();
          message.deletedBy = req.user._id;
          message.originalContent = message.content;
          message.content = 'ข้อความนี้ถูกลบแล้ว';
          message.messageType = 'deleted';

          await message.save();

          console.log('✅ Message soft deleted successfully');

          res.json({
            success: true,
            message: 'Message deleted successfully',
            deletedMessage: {
              id: message._id,
              isDeleted: true,
              deletedAt: message.deletedAt
            }
          });
        } else {
          return res.status(403).json({
            success: false,
            error: 'You can only delete your own messages'
          });
        }
      } else {
        return res.status(404).json({
          success: false,
          error: 'Message not found'
        });
      }
    } else {
      return res.status(404).json({
        success: false,
        error: 'Chat not found'
      });
    }

  } catch (error) {
    console.error('❌ Soft delete message error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to delete message'
    });
  }
});

// 🔥 Update Message
app.put('/api/chats/:chatId/messages/:messageId', authenticateToken, async (req, res) => {
  try {
    const { chatId, messageId } = req.params;
    const { content } = req.body;
    
    console.log('✏️ Updating message:', messageId, 'from chat:', chatId);

    const chat = await Chat.findOne({
      _id: chatId,
      participants: req.user._id
    });

    if (chat) {
      const message = await Message.findOne({
        _id: messageId,
        chatId: chatId
      });

      if (message) {
        if (message.senderId.toString() === req.user._id.toString()) {
          if (!message.isDeleted) {
            message.content = content;
            message.updatedAt = new Date();

            await message.save();

            if (chat.lastMessage === message.originalContent) {
              chat.lastMessage = content;
              await chat.save();
            }

            console.log('✅ Message updated successfully');

            res.json({
              success: true,
              message: 'Message updated successfully',
              updatedMessage: {
                id: message._id,
                content: message.content,
                updatedAt: message.updatedAt
              }
            });
          } else {
            return res.status(400).json({
              success: false,
              error: 'Cannot edit deleted message'
            });
          }
        } else {
          return res.status(403).json({
            success: false,
            error: 'You can only edit your own messages'
          });
        }
      } else {
        return res.status(404).json({
          success: false,
          error: 'Message not found'
        });
      }
    } else {
      return res.status(404).json({
        success: false,
        error: 'Chat not found'
      });
    }

  } catch (error) {
    console.error('❌ Update message error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to update message'
    });
  }
});

// ⌨️ Typing Indicator
app.post('/api/chats/:chatId/typing', authenticateToken, async (req, res) => {
  try {
    const { chatId } = req.params;
    const { isTyping } = req.body;
    
    // In a real-time app with Socket.io, you would emit this event.
    // For REST API, we just acknowledge the request.
    // You could potentially store this in Redis or DB if polling is used.
    
    res.json({ success: true });
  } catch (error) {
    console.error('❌ Typing indicator error:', error);
    res.status(500).json({ success: false, error: 'Failed to send typing indicator' });
  }
});

// 🔍 Global Search
app.get('/api/search', authenticateToken, async (req, res) => {
  try {
    const { q, types } = req.query;
    if (!q || typeof q !== 'string') return res.status(400).json({ success: false, error: 'Query required' });

    const searchTerm = escapeRegex(q.trim());
    // Basic search implementation - expand as needed
    const users = await User.find({ username: { $regex: searchTerm, $options: 'i' } }).limit(5);
    const chats = await Chat.find({ title: { $regex: searchTerm, $options: 'i' }, participants: req.user._id }).limit(5);

    res.json({ success: true, results: { users, chats } });
  } catch (error) {
    console.error('❌ Search error:', error);
    res.status(500).json({ success: false, error: 'Search failed' });
  }
});

// =============================================
// 📨 NOTIFICATION API ROUTES
// =============================================

// 📱 Get User Notifications
app.get('/api/notifications', authenticateToken, async (req, res) => {
  try {
    const { 
      page = 1, 
      limit = 20,
      type,
      unreadOnly = false,
      archived = false
    } = req.query;
    
    const skip = (page - 1) * limit;

    console.log('📨 Fetching notifications for user:', req.user._id, {
      page, limit, type, unreadOnly
    });

    const query = {
      userId: req.user._id,
      isArchived: archived === 'true'
    };

    if (type) {
      query.type = type;
    }

    if (unreadOnly === 'true') {
      query.isRead = false;
    }

    const notifications = await Notification.find(query)
      .sort({ createdAt: -1, priority: -1 })
      .skip(skip)
      .limit(parseInt(limit))
      .lean();

    const total = await Notification.countDocuments(query);
    const unreadCount = await Notification.countDocuments({
      userId: req.user._id,
      isRead: false,
      isArchived: false
    });

    // ฟังก์ชันสร้าง badge สำหรับประเภทต่างๆ
    function _getBadgeForType(type) {
      const badges = {
        'wallet_transaction': '💰',
        'wallet_points': '⭐',
        'chat_message': '💬',
        'chat_call': '📞',
        'friend_request': '👤',
        'friend_accept': '🤝',
        'profile_visit': '👁️',
        'profile_update': '✏️',
        'bank_service': '🏦',
        'identity_verify': '✅',
        'system_alert': '⚡',
        'reward_earned': '🎁'
      };
      
      return badges[type] || '🔔';
    }

    // ✅ แปลงเป็นรูปแบบสำหรับ Frontend
    const formattedNotifications = notifications.map(notif => ({
      id: notif._id,
      type: notif.type,
      title: notif.title,
      message: notif.message,
      icon: notif.icon,
      color: notif.color,
      data: notif.data || {},
      isRead: notif.isRead,
      priority: notif.priority,
      createdAt: notif.createdAt,
      timeAgo: _getTimeAgo(notif.createdAt),
      badge: _getBadgeForType(notif.type)
    }));

    console.log('✅ Found', formattedNotifications.length, 'notifications');

    res.json({
      success: true,
      notifications: formattedNotifications,
      stats: {
        total,
        unreadCount,
        page: parseInt(page),
        limit: parseInt(limit),
        pages: Math.ceil(total / limit)
      }
    });

  } catch (error) {
    console.error('❌ Get notifications error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch notifications'
    });
  }
});

// 👁️ Mark Notification as Read
app.put('/api/notifications/:id/read', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;

    console.log('👁️ Marking notification as read:', id);

    const notification = await Notification.findOne({
      _id: id,
      userId: req.user._id
    });

    if (!notification) {
      return res.status(404).json({
        success: false,
        error: 'Notification not found'
      });
    }

    if (!notification.isRead) {
      notification.isRead = true;
      notification.readAt = new Date();
      await notification.save();
      
      console.log('✅ Notification marked as read');
    }

    res.json({
      success: true,
      message: 'Notification marked as read',
      notificationId: id,
      isRead: true
    });

  } catch (error) {
    console.error('❌ Mark as read error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to mark notification as read'
    });
  }
});

// 👁️ Mark All Notifications as Read
app.put('/api/notifications/read-all', authenticateToken, async (req, res) => {
  try {
    console.log('👁️ Marking all notifications as read for user:', req.user._id);

    const result = await Notification.updateMany(
      {
        userId: req.user._id,
        isRead: false,
        isArchived: false
      },
      {
        $set: {
          isRead: true,
          readAt: new Date()
        }
      }
    );

    console.log('✅ Marked', result.modifiedCount, 'notifications as read');

    res.json({
      success: true,
      message: `Marked ${result.modifiedCount} notifications as read`,
      count: result.modifiedCount
    });

  } catch (error) {
    console.error('❌ Mark all as read error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to mark all notifications as read'
    });
  }
});

// 🗑️ Archive Notification
app.put('/api/notifications/:id/archive', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;

    console.log('🗑️ Archiving notification:', id);

    const notification = await Notification.findOne({
      _id: id,
      userId: req.user._id
    });

    if (!notification) {
      return res.status(404).json({
        success: false,
        error: 'Notification not found'
      });
    }

    notification.isArchived = true;
    await notification.save();

    console.log('✅ Notification archived');

    res.json({
      success: true,
      message: 'Notification archived',
      notificationId: id,
      isArchived: true
    });

  } catch (error) {
    console.error('❌ Archive notification error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to archive notification'
    });
  }
});

// 📊 Get Notification Stats
app.get('/api/notifications/stats', authenticateToken, async (req, res) => {
  try {
    console.log('📊 Getting notification stats for user:', req.user._id);

    const stats = await Notification.aggregate([
      {
        $match: {
          userId: req.user._id,
          isArchived: false
        }
      },
      {
        $group: {
          _id: '$type',
          count: { $sum: 1 },
          unreadCount: {
            $sum: { $cond: [{ $eq: ['$isRead', false] }, 1, 0] }
          }
        }
      },
      {
        $project: {
          type: '$_id',
          count: 1,
          unreadCount: 1,
          _id: 0
        }
      }
    ]);

    const totalCount = await Notification.countDocuments({
      userId: req.user._id,
      isArchived: false
    });

    const unreadTotal = await Notification.countDocuments({
      userId: req.user._id,
      isRead: false,
      isArchived: false
    });

    const recentNotifications = await Notification.find({
      userId: req.user._id,
      isArchived: false
    })
    .sort({ createdAt: -1 })
    .limit(5)
    .select('type title message isRead createdAt')
    .lean();

    console.log('✅ Notification stats loaded');

    res.json({
      success: true,
      stats: {
        total: totalCount,
        unread: unreadTotal,
        byType: stats,
        recent: recentNotifications.map(n => ({
          type: n.type,
          title: n.title,
          message: n.message,
          isRead: n.isRead,
          timeAgo: _getTimeAgo(n.createdAt)
        }))
      }
    });

  } catch (error) {
    console.error('❌ Get notification stats error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to get notification stats'
    });
  }
});

// 🔄 Check New Notifications
app.get('/api/notifications/new', authenticateToken, async (req, res) => {
  try {
    const { since } = req.query;
    const query = { userId: req.user._id, isRead: false };
    
    if (since && typeof since === 'string') {
      query.createdAt = { $gt: new Date(since) };
    }

    const notifications = await Notification.find(query).sort({ createdAt: -1 }).limit(20);
    res.json({ success: true, notifications });
  } catch (error) {
    console.error('❌ Check new notifications error:', error);
    res.status(500).json({ success: false, error: 'Failed to check new notifications' });
  }
});

// 🎯 Get Notifications by Type
app.get('/api/notifications/type/:type', authenticateToken, async (req, res) => {
  try {
    const { type } = req.params;
    const { page = 1, limit = 20 } = req.query;
    const skip = (page - 1) * limit;

    const notifications = await Notification.find({ 
      userId: req.user._id, 
      type: type 
    })
    .sort({ createdAt: -1 })
    .skip(skip)
    .limit(parseInt(limit));

    res.json({ success: true, notifications });
  } catch (error) {
    console.error('❌ Get notifications by type error:', error);
    res.status(500).json({ success: false, error: 'Failed to get notifications' });
  }
});

// 👥 Send Friend Request Push Notification
app.post('/api/friend/push-notification', authenticateToken, async (req, res) => {
  // Logic handled by createFriendRequestNotification usually, but endpoint provided for manual trigger
  res.json({ success: true, message: 'Notification sent' });
});

// =============================================
// ⚙️ SETTINGS & OTHER ROUTES
// =============================================

// 🚪 User Logout
app.post('/api/logout', authenticateToken, async (req, res) => {
  try {
    console.log('🚪 User logout:', req.user._id);

    req.user.authToken = null;
    req.user.tokenExpiry = null;
    await req.user.save();

    console.log('✅ User logged out successfully');

    res.json({
      success: true,
      message: 'Logged out successfully'
    });

  } catch (error) {
    console.error('❌ Logout error:', error);
    res.status(500).json({
      success: false,
      error: 'Logout failed'
    });
  }
});

// ⚙️ Get App Settings
app.get('/api/settings', async (req, res) => {
  try {
    console.log('📥 Received request for app settings');
    
    let settings = await AppSettings.findOne({ type: 'default_settings' });
    
    if (!settings) {
      console.log('🆕 Creating new default settings');
      settings = await AppSettings.create({ 
        type: 'default_settings',
        language: 'en',
        theme: 'white'
      });
    }

    const mourningSettings = await MourningSettings.findOne({ type: 'mourning_settings' });
    const isMourning = mourningSettings?.isMourningPeriod || false;
    
    console.log('✅ Sending app settings with mourning status:', {
      language: settings.language,
      theme: settings.theme,
      isMourning: isMourning
    });
    
    res.json({
      success: true,
      settings: {
        language: settings.language,
        theme: settings.theme
      },
      mourning: {
        isMourningPeriod: isMourning,
        mourningMessage: mourningSettings?.mourningMessage || '',
        mourningTheme: mourningSettings?.mourningTheme || 'black_ribbon'
      }
    });
  } catch (error) {
    console.error('❌ Settings error:', error);
    res.json({
      success: true,
      settings: {
        language: 'en',
        theme: 'white'
      },
      mourning: {
        isMourningPeriod: false,
        mourningMessage: '',
        mourningTheme: 'black_ribbon'
      }
    });
  }
});

// ⚫ Get Mourning Settings
app.get('/api/mourning', async (req, res) => {
  try {
    console.log('⚫ Received request for mourning settings');
    
    let mourningSettings = await MourningSettings.findOne({ type: 'mourning_settings' });
    
    if (!mourningSettings) {
      mourningSettings = await MourningSettings.create({
        type: 'mourning_settings',
        isMourningPeriod: false,
        mourningMessage: '',
        mourningTheme: 'black_ribbon'
      });
    }

    res.json({
      success: true,
      mourning: {
        isMourningPeriod: mourningSettings.isMourningPeriod,
        mourningMessage: mourningSettings.mourningMessage,
        mourningTheme: mourningSettings.mourningTheme,
        startDate: mourningSettings.startDate,
        endDate: mourningSettings.endDate
      }
    });
  } catch (error) {
    console.error('❌ Mourning settings error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to get mourning settings'
    });
  }
});

// ⚫ Update Mourning Settings (Admin only)
app.put('/api/mourning', authenticateToken, async (req, res) => {
  try {
    if (req.user.userType !== 'admin') {
      return res.status(403).json({
        success: false,
        error: 'Access denied. Admin only.'
      });
    }

    const { isMourningPeriod, mourningMessage, mourningTheme, startDate, endDate } = req.body;
    
    console.log('⚫ Updating mourning settings:', { 
      isMourningPeriod, 
      mourningMessage,
      mourningTheme 
    });

    const mourningSettings = await MourningSettings.findOneAndUpdate(
      { type: 'mourning_settings' },
      { 
        isMourningPeriod: isMourningPeriod || false,
        mourningMessage: mourningMessage || '',
        mourningTheme: mourningTheme || 'black_ribbon',
        startDate: startDate ? new Date(startDate) : null,
        endDate: endDate ? new Date(endDate) : null,
        updatedAt: new Date()
      },
      { new: true, upsert: true }
    );

    console.log('✅ Mourning settings updated successfully');

    res.json({
      success: true,
      message: 'Mourning settings updated successfully',
      mourning: {
        isMourningPeriod: mourningSettings.isMourningPeriod,
        mourningMessage: mourningSettings.mourningMessage,
        mourningTheme: mourningSettings.mourningTheme,
        startDate: mourningSettings.startDate,
        endDate: mourningSettings.endDate
      }
    });
  } catch (error) {
    console.error('❌ Update mourning settings error:', error);
    res.status(500).json({ 
      success: false,
      error: 'Failed to update mourning settings' 
    });
  }
});

// ⚙️ Update App Settings
app.put('/api/settings', async (req, res) => {
  try {
    const { language, theme } = req.body;
    
    console.log('📝 Updating app settings:', { language, theme });
    
    const settings = await AppSettings.findOneAndUpdate(
      { type: 'default_settings' },
      { 
        language: language || 'en',
        theme: theme || 'white', 
        updatedAt: new Date()
      },
      { new: true, upsert: true }
    );
    
    console.log('✅ App settings updated successfully:', {
      language: settings.language,
      theme: settings.theme
    });
    
    res.json({
      success: true,
      settings: {
        language: settings.language,
        theme: settings.theme
      }
    });
  } catch (error) {
    console.error('❌ Update settings error:', error);
    res.status(500).json({ 
      success: false,
      error: 'Failed to update settings' 
    });
  }
});

// ⚙️ Update User Settings
app.put('/api/user/settings', authenticateToken, async (req, res) => {
  try {
    const { language, theme } = req.body;

    console.log('⚙️ Updating user settings:', { 
      userId: req.user._id, 
      language, 
      theme 
    });

    req.user.settings.language = language || req.user.settings.language;
    req.user.settings.theme = theme || req.user.settings.theme;
    req.user.updatedAt = new Date();

    await req.user.save();

    console.log('✅ User settings updated successfully:', req.user.settings);

    res.json({
      success: true,
      message: 'Settings updated successfully',
      settings: req.user.settings
    });
  } catch (error) {
    console.error('❌ Update user settings error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to update settings'
    });
  }
});

// 🔔 Update Notification Settings
app.put('/api/user/notification-settings', authenticateToken, async (req, res) => {
  try {
    const settings = req.body;
    req.user.notificationSettings = { ...req.user.notificationSettings, ...settings };
    await req.user.save();
    res.json({ success: true, message: 'Notification settings updated', settings: req.user.notificationSettings });
  } catch (error) {
    console.error('❌ Update notification settings error:', error);
    res.status(500).json({ success: false, error: 'Failed to update settings' });
  }
});

// 🔔 Get Notification Settings
app.get('/api/user/notification-settings', authenticateToken, async (req, res) => {
  try {
    res.json({ 
      success: true, 
      settings: req.user.notificationSettings || {
        chatNotifications: true, friendRequestNotifications: true, systemNotifications: true, soundEnabled: true, vibrationEnabled: true
      }
    });
  } catch (error) {
    console.error('❌ Get notification settings error:', error);
    res.status(500).json({ success: false, error: 'Failed to get settings' });
  }
});

// =============================================
// 📱 FCM TOKEN MANAGEMENT API ROUTES
// =============================================

// ✅ แก้ไข: middleware validation ต้องประกาศเป็น array และ function
const fcmTokenValidation = [
  body('fcmToken')
    .notEmpty()
    .withMessage('FCM token is required')
    .isLength({ min: 10 })
    .withMessage('FCM token must be at least 10 characters'),
  body('platform')
    .optional()
    .isIn(['android', 'ios', 'web'])
    .withMessage('Platform must be android, ios, or web')
];

// ✅ แยก handler function ออกมา
const fcmTokenUpdateHandler = async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        error: errors.array()[0].msg
      });
    }

    const { fcmToken, platform = 'android' } = req.body;

    console.log('📱 Updating FCM token for user:', {
      userId: req.user._id,
      username: req.user.username,
      platform: platform,
      tokenLength: fcmToken.length,
      tokenPreview: fcmToken.substring(0, 20) + '...'
    });

    // 🔄 อัปเดต FCM token ใน database
    req.user.fcmToken = fcmToken;
    req.user.updatedAt = new Date();
    await req.user.save();

    console.log('✅ FCM token updated successfully for user:', req.user._id);

    // ✅ สร้างการแจ้งเตือนระบบ
    await createSystemNotification(req.user._id, {
      alertType: 'info',
      message: `FCM token updated for ${platform}`,
      actionUrl: null
    });

    res.json({
      success: true,
      message: 'FCM token updated successfully',
      tokenUpdated: true,
      platform: platform,
      updatedAt: req.user.updatedAt,
      userInfo: {
        username: req.user.username,
        email: req.user.email
      }
    });

  } catch (error) {
    console.error('❌ Update FCM token error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to update FCM token: ' + error.message
    });
  }
};

// 🔥 Update FCM Token สำหรับ Push Notifications
app.put('/api/user/fcm-token', authenticateToken, fcmTokenValidation, fcmTokenUpdateHandler);

// 🔥 POST alias for FCM Token update (Compatibility)
app.post('/api/user/fcm-token', authenticateToken, fcmTokenValidation, fcmTokenUpdateHandler);

// 🔥 Aliases for FCM Token registration for client compatibility
const fcmTokenAliases = [
  '/api/user/device-token',
  '/api/notifications/register',
  '/api/fcm/register',
  '/api/device/register'
];

fcmTokenAliases.forEach(alias => {
  app.put(alias, authenticateToken, fcmTokenValidation, fcmTokenUpdateHandler);
  app.post(alias, authenticateToken, fcmTokenValidation, fcmTokenUpdateHandler);
});

// 🔍 Get FCM Token Status
app.get('/api/user/fcm-token/status', authenticateToken, async (req, res) => {
  try {
    console.log('🔍 Checking FCM token status for user:', {
      userId: req.user._id,
      username: req.user.username
    });

    const hasToken = !!req.user.fcmToken;
    const tokenAge = hasToken ? 
      Math.floor((Date.now() - req.user.updatedAt) / (1000 * 60 * 60 * 24)) : 0;

    res.json({
      success: true,
      isRegistered: hasToken,
      lastUpdated: req.user.updatedAt,
      platform: 'android',
      hasToken: hasToken,
      tokenLength: hasToken ? req.user.fcmToken.length : 0,
      tokenAgeDays: tokenAge,
      needsRefresh: tokenAge > 30 // รีเฟรชทุก 30 วัน
    });

  } catch (error) {
    console.error('❌ Get FCM token status error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to check FCM token status'
    });
  }
});

// 🗑️ Delete FCM Token (สำหรับ logout หรือยกเลิกการแจ้งเตือน)
app.delete('/api/user/fcm-token', authenticateToken, async (req, res) => {
  try {
    console.log('🗑️ Deleting FCM token for user:', {
      userId: req.user._id,
      username: req.user.username,
      hadToken: !!req.user.fcmToken
    });

    const hadToken = !!req.user.fcmToken;
    req.user.fcmToken = null;
    req.user.updatedAt = new Date();
    await req.user.save();

    if (hadToken) {
      // ✅ สร้างการแจ้งเตือนระบบ
      await createSystemNotification(req.user._id, {
        alertType: 'warning',
        message: 'FCM token removed. Push notifications disabled.',
        actionUrl: null
      });
    }

    console.log('✅ FCM token deleted successfully');

    res.json({
      success: true,
      message: 'FCM token deleted successfully',
      tokenDeleted: true,
      hadToken: hadToken,
      updatedAt: req.user.updatedAt
    });

  } catch (error) {
    console.error('❌ Delete FCM token error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to delete FCM token'
    });
  }
});

// 📤 Send Push Notification (Generic)
app.post('/api/notifications/push/send', authenticateToken, async (req, res) => {
  const { targetUserId, title, body, data } = req.body;
  const success = await sendPushNotification(targetUserId, { title, body, data });
  res.json({ success, message: success ? 'Sent' : 'Failed' });
});

// 📱 Test Push Notification (สำหรับทดสอบ)
app.post('/api/notifications/push/test', authenticateToken, [
  body('title')
    .notEmpty()
    .withMessage('Title is required'),
  body('body')
    .notEmpty()
    .withMessage('Body is required')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        error: errors.array()[0].msg
      });
    }

    const { title, body } = req.body;

    console.log('🧪 Sending test push notification to self:', {
      userId: req.user._id,
      username: req.user.username,
      title: title,
      body: body
    });

    if (!req.user.fcmToken) {
      return res.status(400).json({
        success: false,
        error: 'No FCM token registered for this user'
      });
    }

    // ✅ สร้างการแจ้งเตือนทดสอบ
    await createSystemNotification(req.user._id, {
      alertType: 'test',
      message: `Test: ${title} - ${body}`,
      actionUrl: null
    });

    // TODO: ส่ง push notification จริงผ่าน Firebase Admin SDK
    console.log('📤 [SIMULATED] Push notification sent to:', req.user.fcmToken.substring(0, 30) + '...');

    res.json({
      success: true,
      message: 'Test push notification sent',
      simulated: true,
      details: {
        title: title,
        body: body,
        tokenExists: true,
        timestamp: new Date().toISOString()
      }
    });

  } catch (error) {
    console.error('❌ Test push notification error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to send test push notification'
    });
  }
});

// 🔄 Refresh FCM Token (สำหรับ client ที่ต้องการ token ใหม่)
app.post('/api/user/fcm-token/refresh', authenticateToken, async (req, res) => {
  try {
    console.log('🔄 FCM token refresh requested for user:', {
      userId: req.user._id,
      username: req.user.username,
      currentToken: req.user.fcmToken ? 'exists' : 'none'
    });

    // ไม่ต้องทำอะไรใน server แค่บอกให้ client ส่ง token ใหม่มา
    // Client ควรเรียก updateFCMToken อีกครั้งด้วย token ใหม่

    res.json({
      success: true,
      message: 'Please send new FCM token using update endpoint',
      needsNewToken: true,
      currentTokenStatus: req.user.fcmToken ? 'valid' : 'missing'
    });

  } catch (error) {
    console.error('❌ Refresh FCM token error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to process refresh request'
    });
  }
});
// =============================================
// 📱 END OF FCM TOKEN MANAGEMENT
// =============================================

// 🆔 Change User ID
app.put('/api/user/change-id', authenticateToken, [
  body('newUserId')
    .isLength({ min: 4, max: 20 })
    .withMessage('User ID must be between 4-20 characters')
    .matches(/^[a-zA-Z0-9_]+$/)
    .withMessage('User ID can only contain letters, numbers and underscore')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        error: errors.array()[0].msg
      });
    }

    const { newUserId } = req.body;

    console.log('🆔 User ID change request:', {
      userId: req.user._id,
      newUserId: newUserId
    });

    const existingUser = await User.findOne({ 
      _id: { $ne: req.user._id },
      userId: newUserId 
    });

    if (!existingUser) {
      const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
      if (!req.user.lastUserIdChange || req.user.lastUserIdChange <= thirtyDaysAgo) {
        const oldUserId = req.user.userId;
        req.user.userId = newUserId;
        req.user.lastUserIdChange = new Date();
        req.user.updatedAt = new Date();

        await req.user.save();

        console.log('✅ User ID changed successfully:', { oldUserId, newUserId });

        res.json({
          success: true,
          message: 'User ID changed successfully',
          newUserId: newUserId,
          nextChangeDate: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000)
        });
      } else {
        const daysLeft = Math.ceil((req.user.lastUserIdChange.getTime() - thirtyDaysAgo.getTime()) / (24 * 60 * 60 * 1000));
        return res.status(400).json({
          success: false,
          error: `You can change User ID again in ${daysLeft} days`
        });
      }
    } else {
      return res.status(400).json({
        success: false,
        error: 'User ID already taken'
      });
    }

  } catch (error) {
    console.error('❌ Change User ID error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to change User ID'
    });
  }
});

// 📧 Change Email
app.post('/api/user/change-email', authenticateToken, [
  body('newEmail')
    .isEmail()
    .withMessage('Must be a valid email')
    .normalizeEmail()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        error: errors.array()[0].msg
      });
    }

    const { newEmail } = req.body;

    console.log('📧 Email change request:', {
      userId: req.user._id,
      newEmail: newEmail
    });

    const existingUser = await User.findOne({ 
      _id: { $ne: req.user._id },
      email: newEmail.toLowerCase().trim()
    });

    if (!existingUser) {
      if (req.user.email !== newEmail.toLowerCase().trim()) {
        const oldEmail = req.user.email;
        req.user.email = newEmail.toLowerCase().trim();
        req.user.updatedAt = new Date();

        await req.user.save();

        console.log('✅ Email changed successfully:', { oldEmail, newEmail });

        res.json({
          success: true,
          message: 'Email changed successfully',
          newEmail: newEmail
        });
      } else {
        return res.status(400).json({
          success: false,
          error: 'This is already your current email'
        });
      }
    } else {
      return res.status(400).json({
        success: false,
        error: 'Email already registered'
      });
    }

  } catch (error) {
    console.error('❌ Change email error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to change email'
    });
  }
});

// ⏰ Get ID Change Status
app.get('/api/user/id-change-status', authenticateToken, async (req, res) => {
  try {
    console.log('⏰ Checking ID change status for user:', req.user._id);

    let canChange = true;
    let daysLeft = 0;
    let lastChange = null;

    if (req.user.lastUserIdChange) {
      const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
      
      if (req.user.lastUserIdChange > thirtyDaysAgo) {
        canChange = false;
        const timeDiff = req.user.lastUserIdChange.getTime() - thirtyDaysAgo.getTime();
        daysLeft = Math.ceil(timeDiff / (24 * 60 * 60 * 1000));
      }
      
      lastChange = req.user.lastUserIdChange;
    }

    console.log('✅ ID change status:', { canChange, daysLeft, lastChange });

    res.json({
      success: true,
      canChange: canChange,
      daysLeft: daysLeft,
      lastChange: lastChange,
      nextChangeDate: canChange ? null : new Date(req.user.lastUserIdChange.getTime() + 30 * 24 * 60 * 60 * 1000)
    });

  } catch (error) {
    console.error('❌ ID change status error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to get ID change status'
    });
  }
});

// 🖼️ Upload Profile Picture
app.post('/api/profile/picture', authenticateToken, async (req, res) => {
  try {
    const { imageData } = req.body;

    console.log('🖼️ Profile picture upload for user:', req.user._id);

    if (imageData) {
      if (imageData.startsWith('data:image/')) {
        const base64Data = imageData.replace(/^data:image\/\w+;base64,/, '');
        const buffer = Buffer.from(base64Data, 'base64');
        
        if (buffer.length <= 2 * 1024 * 1024) {
          req.user.profilePicture = imageData;
          req.user.updatedAt = new Date();

          await req.user.save();

          console.log('✅ Profile picture uploaded successfully');

          res.json({
            success: true,
            message: 'Profile picture uploaded successfully',
            profilePicture: imageData
          });
        } else {
          return res.status(400).json({
            success: false,
            error: 'Image size too large. Maximum 2MB allowed.'
          });
        }
      } else {
        return res.status(400).json({
          success: false,
          error: 'Invalid image format. Please use base64 encoded image.'
        });
      }
    } else {
      return res.status(400).json({
        success: false,
        error: 'Image data is required'
      });
    }

  } catch (error) {
    console.error('❌ Upload profile picture error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to upload profile picture'
    });
  }
});

// =============================================
// 👥 GROUP API ROUTES (NEW)
// =============================================

// 👥 Create Group
app.post('/api/groups', authenticateToken, async (req, res) => {
  try {
    const { name, members, description, groupPicture } = req.body;
    
    // Convert member IDs to ObjectIds and include creator
    const participantIds = [...new Set([...members, req.user._id.toString()])];
    
    const newGroup = new Chat({
      participants: participantIds,
      chatType: 'group',
      title: name,
      description: description,
      groupPicture: groupPicture,
      admins: [req.user._id],
      createdBy: req.user._id,
      lastMessage: 'Group created',
      lastMessageTime: new Date()
    });

    await newGroup.save();

    // Create system message
    await Message.create({
      chatId: newGroup._id,
      senderId: req.user._id,
      messageType: 'system',
      content: `Group "${name}" created`
    });

    res.json({ success: true, chat: newGroup, groupId: newGroup._id });
  } catch (error) {
    console.error('❌ Create group error:', error);
    res.status(500).json({ success: false, error: 'Failed to create group' });
  }
});

// 👥 Get Group Info
app.get('/api/groups/:id', authenticateToken, async (req, res) => {
  try {
    const chat = await Chat.findOne({ _id: req.params.id, chatType: 'group' })
      .populate('participants', 'username profilePicture')
      .populate('admins', 'username');
    
    if (!chat) return res.status(404).json({ success: false, error: 'Group not found' });
    
    res.json({ success: true, group: chat });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Failed to get group info' });
  }
});

// 👥 Get Group Members
app.get('/api/groups/:id/members', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { page = 1, limit = 50 } = req.query;
    const skip = (parseInt(page) - 1) * parseInt(limit);

    const chat = await Chat.findOne({
      _id: id,
      chatType: 'group',
      participants: req.user._id
    }).select('participants admins createdBy');

    if (!chat) {
      return res.status(404).json({ success: false, error: 'Group not found or you are not a member' });
    }

    const total = chat.participants.length;

    const members = await User.find({
      _id: { $in: chat.participants }
    })
    .select('username userId profilePicture userType lastLogin')
    .skip(skip)
    .limit(parseInt(limit))
    .lean();

    const formattedMembers = members.map(member => ({
      ...member,
      role: chat.admins.some(adminId => adminId.equals(member._id)) ? 'admin' : (chat.createdBy.equals(member._id) ? 'creator' : 'member')
    }));

    res.json({
      success: true,
      members: formattedMembers,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / parseInt(limit))
      }
    });
  } catch (error) {
    console.error('❌ Get group members error:', error);
    res.status(500).json({ success: false, error: 'Failed to get group members' });
  }
});

// 👥 Update Group
app.put('/api/groups/:id', authenticateToken, async (req, res) => {
  try {
    const { name, description, groupPicture } = req.body;
    

    const chat = await Chat.findOne({ _id: req.params.id, chatType: 'group' });
    if (!chat) return res.status(404).json({ success: false, error: 'Group not found' });

    // Check if admin
    const isAdmin = chat.admins && chat.admins.some(id => id.toString() === req.user._id.toString());
    const isCreator = chat.createdBy && chat.createdBy.toString() === req.user._id.toString();
    

    if (!isAdmin && !isCreator) {
      return res.status(403).json({ success: false, error: 'Only admins can update group settings' });
    }

    if (name) chat.title = name;
    if (description) chat.description = description;
    if (groupPicture) chat.groupPicture = groupPicture;

    await chat.save();
    res.json({ success: true, group: chat });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Failed to update group' });
  }
});

// 👥 Add Members
app.post('/api/groups/:id/members', authenticateToken, async (req, res) => {
  try {
    const { memberIds } = req.body;
    const chat = await Chat.findById(req.params.id);
    
    if (!chat) return res.status(404).json({ success: false, error: 'Group not found' });
    
    // Add new members
    chat.participants = [...new Set([...chat.participants.map(p => p.toString()), ...memberIds])];
    await chat.save();
    
    res.json({ success: true, message: 'Members added' });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Failed to add members' });
  }
});

// 👥 Remove Members
app.delete('/api/groups/:id/members', authenticateToken, async (req, res) => {
  try {
    const { memberIds } = req.body;
    const chat = await Chat.findById(req.params.id);
    
    if (!chat) return res.status(404).json({ success: false, error: 'Group not found' });
    
    chat.participants = chat.participants.filter(p => !memberIds.includes(p.toString()));
    await chat.save();
    
    res.json({ success: true, message: 'Members removed' });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Failed to remove members' });
  }
});

// 👥 Leave Group
app.post('/api/groups/:id/leave', authenticateToken, async (req, res) => {
  try {
    const chat = await Chat.findById(req.params.id);
    if (!chat) return res.status(404).json({ success: false, error: 'Group not found' });
    
    chat.participants = chat.participants.filter(p => p.toString() !== req.user._id.toString());
    await chat.save();
    
    res.json({ success: true, message: 'Left group successfully' });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Failed to leave group' });
  }
});

// 👥 Delete Group (Requested Route)
app.post('/api/groups/:id/delete', authenticateToken, async (req, res) => {
  try {
    const { reason, satisfaction } = req.body;
    console.log(`🗑️ Deleting group ${req.params.id}. Reason: ${reason}, Satisfaction: ${satisfaction}`);

    const chat = await Chat.findOne({ _id: req.params.id, chatType: 'group' });
    
    if (!chat) return res.status(404).json({ success: false, error: 'Group not found' });
    
    // Check if admin
    const isAdmin = chat.admins && chat.admins.some(id => id.toString() === req.user._id.toString());
    const isCreator = chat.createdBy && chat.createdBy.toString() === req.user._id.toString();

    if (!isAdmin && !isCreator) {
      return res.status(403).json({ success: false, error: 'Only admins can delete the group' });
    }

    // Soft delete or hard delete based on requirement. Here we do hard delete for simplicity as per common request
    await Message.deleteMany({ chatId: chat._id });
    await Chat.deleteOne({ _id: chat._id });

    res.json({ success: true, message: 'Group deleted successfully' });
  } catch (error) {
    console.error('❌ Delete group error:', error);
    res.status(500).json({ success: false, error: 'Failed to delete group' });
  }
});

// 👥 Delete Group (Standard DELETE)
app.delete('/api/groups/:id', authenticateToken, async (req, res) => {
  // Reuse logic
  try {
    const chat = await Chat.findOne({ _id: req.params.id, chatType: 'group' });
    if (!chat) return res.status(404).json({ success: false, error: 'Group not found' });
    
    // Check if admin
    const isAdmin = chat.admins && chat.admins.some(id => id.toString() === req.user._id.toString());
    const isCreator = chat.createdBy && chat.createdBy.toString() === req.user._id.toString();

    if (!isAdmin && !isCreator) {
      return res.status(403).json({ success: false, error: 'Only admins can delete the group' });
    }

    await Message.deleteMany({ chatId: chat._id });
    await Chat.deleteOne({ _id: chat._id });
    
    res.json({ success: true, message: 'Group deleted' });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Failed to delete group' });
  }
});

// 👥 Get User Groups
app.get('/api/groups', authenticateToken, async (req, res) => {
  try {
    const groups = await Chat.find({ 
      participants: req.user._id, 
      chatType: 'group' 
    }).sort({ lastMessageTime: -1 });
    
    res.json({ success: true, groups });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Failed to get groups' });
  }
});

// 👥 Get Group Messages (Alias to chats messages)
app.get('/api/groups/:id/messages', authenticateToken, async (req, res) => {
  // Redirect to existing logic
  req.params.chatId = req.params.id;
  // We can just call the logic or redirect internally, but for express, let's just copy the logic or use a shared handler.
  // For simplicity in this diff, I'll just query it.
  try {
    const messages = await Message.find({ chatId: req.params.id, isDeleted: false })
      .populate('senderId', 'username profilePicture')
      .sort({ timestamp: 1 });
      
    const formattedMessages = messages.map(msg => ({
      id: msg._id,
      sender: msg.senderId.username,
      message: msg.content,
      timestamp: msg.timestamp,
      isMe: msg.senderId._id.toString() === req.user._id.toString(),
      messageType: msg.messageType,
      profilePicture: msg.senderId.profilePicture
    }));
    
    res.json({ success: true, messages: formattedMessages });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Failed to get messages' });
  }
});

// 👥 Send Group Message
app.post('/api/groups/:id/messages', authenticateToken, async (req, res) => {
  try {
    const { content, messageType, fileUrl, fileName } = req.body;
    const newMessage = new Message({
      chatId: req.params.id,
      senderId: req.user._id,
      messageType: messageType || 'text',
      content: content,
      // If you add fileUrl/fileName to Message schema, save them here
    });
    await newMessage.save();
    
    // Update chat last message
    await Chat.findByIdAndUpdate(req.params.id, {
      lastMessage: messageType === 'text' ? content : `Sent a ${messageType}`,
      lastMessageTime: new Date()
    });

    res.json({ success: true, message: 'Message sent' });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Failed to send message' });
  }
});

// 👥 Upload Group Picture
app.post('/api/groups/:id/picture', authenticateToken, async (req, res) => {
  try {
    const { imageData } = req.body;
    await Chat.findByIdAndUpdate(req.params.id, { groupPicture: imageData });
    res.json({ success: true, message: 'Group picture updated' });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Failed to upload picture' });
  }
});

// 👥 Update Group Member Roles
app.put('/api/groups/:id/members/roles', authenticateToken, async (req, res) => {
  try {
    const { memberIds, roles } = req.body;
    
    if (!memberIds || !roles || !Array.isArray(memberIds) || !Array.isArray(roles) || memberIds.length !== roles.length) {
      return res.status(400).json({ success: false, error: 'Invalid input: memberIds and roles must be arrays of equal length' });
    }

    const chat = await Chat.findOne({ _id: req.params.id, chatType: 'group' });
    if (!chat) return res.status(404).json({ success: false, error: 'Group not found' });

    // Check if requester is admin or creator
    const isRequesterAdmin = chat.admins && chat.admins.some(id => id.toString() === req.user._id.toString());
    const isRequesterCreator = chat.createdBy && chat.createdBy.toString() === req.user._id.toString();

    if (!isRequesterAdmin && !isRequesterCreator) {
      return res.status(403).json({ success: false, error: 'Only admins can update member roles' });
    }

    // Update roles
    memberIds.forEach((memberId, index) => {
      const role = roles[index];
      
      // Ensure member is part of the group
      if (chat.participants.some(p => p.toString() === memberId)) {
        if (role === 'admin') {
          // Add to admins if not already there
          if (!chat.admins.some(a => a.toString() === memberId)) {
            chat.admins.push(memberId);
          }
        } else if (role === 'member') {
          // Remove from admins
          chat.admins = chat.admins.filter(a => a.toString() !== memberId);
        }
      }
    });

    await chat.save();
    
    res.json({ success: true, message: 'Member roles updated successfully' });
  } catch (error) {
    console.error('❌ Update member roles error:', error);
    res.status(500).json({ success: false, error: 'Failed to update member roles' });
  }
});

// =============================================
// 🗂️ FILE UPLOAD ROUTES
// =============================================

app.post('/api/upload', authenticateToken, upload.single('file'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ success: false, error: 'No file uploaded' });

    const fileUrl = `${req.protocol}://${req.get('host')}/uploads/${req.file.filename}`;

    const newFile = new File({
        filename: req.file.filename,
        originalName: req.file.originalname,
        mimetype: req.file.mimetype,
        size: req.file.size,
        url: fileUrl,
        uploadedBy: req.user._id,
        chatId: req.body.chatId || req.body.groupId
    });

    await newFile.save();

    res.json({
      success: true,
      fileId: newFile._id,
      fileUrl: fileUrl,
      fileName: req.file.originalname,
      fileType: req.file.mimetype
    });
  } catch (error) {
    console.error('❌ Upload error:', error);
    if (req.file) {
      fs.unlink(req.file.path, (err) => {
        if (err) console.error('❌ Error deleting orphaned file:', err);
      });
    }
    res.status(500).json({ success: false, error: 'Upload failed' });
  }
});

// 📁 Get File Info
app.get('/api/files/:fileId', authenticateToken, async (req, res) => {
  try {
    const file = await File.findById(req.params.fileId).populate('uploadedBy', 'username userId');
    if (!file) {
      return res.status(404).json({ success: false, error: 'File not found' });
    }

    // Authorization: check if user is part of the chat the file was uploaded to
    if (file.chatId) {
      const chat = await Chat.findOne({ _id: file.chatId, participants: req.user._id });
      if (!chat) {
        return res.status(403).json({ success: false, error: 'Access denied' });
      }
    } else {
      // If no chat is associated, only the uploader can see it
      if (file.uploadedBy._id.toString() !== req.user._id.toString()) {
        return res.status(403).json({ success: false, error: 'Access denied' });
      }
    }

    res.json({ success: true, file: file });
  } catch (error) {
    console.error('❌ Get file info error:', error);
    res.status(500).json({ success: false, error: 'Failed to get file info' });
  }
});

// 🗑️ Delete File
app.delete('/api/files/:fileId', authenticateToken, async (req, res) => {
  try {
    const file = await File.findById(req.params.fileId);
    if (!file) {
      return res.status(404).json({ success: false, error: 'File not found' });
    }

    if (file.uploadedBy.toString() !== req.user._id.toString()) {
      return res.status(403).json({ success: false, error: 'You are not authorized to delete this file' });
    }

    const filePath = path.join('uploads', file.filename);
    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
    }

    await File.deleteOne({ _id: file._id });

    res.json({ success: true, message: 'File deleted successfully' });
  } catch (error) {
    console.error('❌ Delete file error:', error);
    res.status(500).json({ success: false, error: 'Failed to delete file' });
  }
});

// =============================================
// 📤 MEDIA UPLOAD ENDPOINTS
// =============================================

// 🎥 Get Videos Feed
app.get('/api/videos/feed', authenticateToken, async (req, res) => {
  try {
    const { page = 1, limit = 10 } = req.query;
    const skip = (parseInt(page) - 1) * parseInt(limit);

    console.log('🎥 Fetching videos feed for user:', req.user._id, { page, limit });

    // Query: Completed videos that are public OR owned by the user
    const query = {
      status: 'completed',
      mimeType: { $regex: /^video\// },
      $or: [
        { visibility: 'public' },
        { userId: req.user._id }
      ]
    };

    const videos = await MediaUpload.find(query)
      .populate('userId', 'username profilePicture userId')
      .sort({ uploadedAt: -1 })
      .skip(skip)
      .limit(parseInt(limit))
      .lean();

    const total = await MediaUpload.countDocuments(query);

    const formattedVideos = videos.map(video => ({
      id: video.uploadId,
      _id: video._id,
      title: video.title,
      description: video.description,
      videoUrl: video.fileUrl,
      thumbnailUrl: video.thumbnailUrl,
      duration: video.duration,
      fileSize: video.fileSize,
      mimeType: video.mimeType,
      uploadedAt: video.uploadedAt,
      visibility: video.visibility,
      uploader: video.userId ? {
        id: video.userId.userId || video.userId._id,
        username: video.userId.username,
        profilePicture: video.userId.profilePicture
      } : null,
      isMine: video.userId && video.userId._id.toString() === req.user._id.toString()
    }));

    res.json({
      success: true,
      videos: formattedVideos,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / parseInt(limit))
      }
    });

  } catch (error) {
    console.error('❌ Get videos feed error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch videos feed'
    });
  }
});

// 📤 POST /api/upload/media - Upload media content (video, photo, camera recording)
app.post('/api/upload/media', authenticateToken, mediaUpload.single('file'), async (req, res) => {
  try {
    console.log('🔄 Media upload started:', {
      file: req.file ? req.file.originalname : 'NO FILE',
      fileName: req.body.fileName,
      fileType: req.body.fileType,
      userId: req.user._id
    });

    if (!req.file) {
      console.error('❌ No file uploaded');
      return res.status(400).json({ success: false, error: 'No file uploaded' });
    }

    // ✅ รับค่าพารามิเตอร์ใหม่ๆ จาก Client
    const { 
      fileName, 
      fileType, 
      title, 
      description, 
      visibility,
      commentPermission,
      shareToStory,
      shareToGroups, // JSON string
      scheduledTime,
      collaborators // JSON string
    } = req.body;

    if (!fileType || !title) {
      console.error('❌ Missing required fields:', { fileType, title });
      // Clean up uploaded file
      if (fs.existsSync(req.file.path)) {
        fs.unlinkSync(req.file.path);
      }
      return res.status(400).json({ success: false, error: 'Missing required fields: fileType and title' });
    }

    // Validate fileType
    if (!['video', 'photo', 'camera'].includes(fileType)) {
      console.error('❌ Invalid fileType:', fileType);
      if (fs.existsSync(req.file.path)) {
        fs.unlinkSync(req.file.path);
      }
      return res.status(400).json({ success: false, error: 'Invalid fileType. Allowed: video, photo, camera' });
    }

    const uploadId = Date.now() + '-' + Math.round(Math.random() * 1E9);
    const fileUrl = `${req.protocol}://${req.get('host')}/uploads/media/${req.file.filename}`;

    console.log('💾 Creating MediaUpload record:', {
      uploadId,
      fileName: fileName || req.file.originalname,
      fileType,
      fileSize: req.file.size
    });

    // ✅ แปลงข้อมูล JSON string กลับเป็น Array (เพราะส่งมาเป็น FormData)
    let parsedGroups = [];
    if (shareToGroups) {
      try {
        parsedGroups = JSON.parse(shareToGroups);
      } catch(e) { console.error('Error parsing shareToGroups:', e); }
    }

    let parsedCollaborators = [];
    if (collaborators) {
      try {
        parsedCollaborators = JSON.parse(collaborators);
      } catch(e) { console.error('Error parsing collaborators:', e); }
    }

    // Create MediaUpload record
    const mediaUploadRecord = new MediaUpload({
      uploadId: uploadId,
      userId: req.user._id,
      fileName: fileName || req.file.originalname,
      fileType: fileType,
      mimeType: req.file.mimetype,
      fileSize: req.file.size,
      title: title,
      description: description || '',
      filePath: req.file.path,
      fileUrl: fileUrl,
      status: 'completed',
      
      // ✅ บันทึกค่า Settings ลงฐานข้อมูล
      visibility: visibility || 'public',
      commentPermission: commentPermission || 'public',
      shareToStory: shareToStory === 'true', // ค่าจาก form-data เป็น string
      shareToGroups: parsedGroups.filter(id => mongoose.Types.ObjectId.isValid(id)),
      scheduledTime: scheduledTime ? new Date(scheduledTime) : null,
      collaborators: parsedCollaborators.filter(id => mongoose.Types.ObjectId.isValid(id)),
      
      uploadProgress: 100,
      completedAt: new Date()
    });

    await mediaUploadRecord.save();
    console.log('✅ MediaUpload record saved');

    console.log('💾 Creating UploadProgress record:', { uploadId });

    // Create UploadProgress record
    const uploadProgressRecord = new UploadProgress({
      uploadId: uploadId,
      userId: req.user._id,
      bytesUploaded: req.file.size,
      totalBytes: req.file.size,
      percentComplete: 100,
      status: 'completed',
      completedTime: new Date()
    });

    await uploadProgressRecord.save();
    console.log('✅ UploadProgress record saved');

    console.log('✅ Media uploaded successfully:', {
      uploadId: uploadId,
      fileName: fileName || req.file.originalname,
      fileType: fileType,
      fileSize: req.file.size,
      status: 'completed'
    });

    res.status(201).json({
      success: true,
      message: 'Media uploaded successfully',
      uploadId: uploadId,
      fileUrl: fileUrl,
      fileName: fileName || req.file.originalname,
      fileType: fileType,
      fileSize: req.file.size,
      status: 'completed'
    });

  } catch (error) {
    console.error('❌ Media upload error:', {
      message: error.message,
      stack: error.stack,
      name: error.name,
      code: error.code,
      fullError: JSON.stringify(error, null, 2)
    });
    
    // Clean up uploaded file on error
    if (req.file && fs.existsSync(req.file.path)) {
      try {
        fs.unlinkSync(req.file.path);
        console.log('✅ Cleanup: File deleted');
      } catch (unlinkError) {
        console.error('❌ Error deleting file:', unlinkError.message);
      }
    }
    
    res.status(500).json({ 
      success: false, 
      error: 'Media upload failed: ' + error.message,
      details: error.code || error.name 
    });
  }
}, (err, req, res, next) => {
  // Multer error handling middleware
  console.error('❌ Multer error:', {
    message: err.message,
    code: err.code,
    field: err.field
  });
  
  res.status(400).json({
    success: false,
    error: 'File upload error: ' + err.message
  });
});

// 📊 GET /api/upload/progress/:uploadId - Get upload progress
app.get('/api/upload/progress/:uploadId', authenticateToken, async (req, res) => {
  try {
    const { uploadId } = req.params;

    const uploadProgress = await UploadProgress.findOne({ uploadId: uploadId });

    if (!uploadProgress) {
      return res.status(404).json({ success: false, error: 'Upload not found' });
    }

    // Verify ownership
    if (uploadProgress.userId.toString() !== req.user._id.toString()) {
      return res.status(403).json({ success: false, error: 'Access denied: this is not your upload' });
    }

    const mediaUpload = await MediaUpload.findOne({ uploadId: uploadId });

    res.json({
      success: true,
      uploadId: uploadId,
      progress: {
        bytesUploaded: uploadProgress.bytesUploaded,
        totalBytes: uploadProgress.totalBytes,
        percentComplete: uploadProgress.percentComplete,
        status: uploadProgress.status,
        speed: uploadProgress.speed, // bytes per second
        remainingTime: uploadProgress.remainingTime, // seconds
        startTime: uploadProgress.startTime,
        lastUpdateTime: uploadProgress.lastUpdateTime,
        completedTime: uploadProgress.completedTime
      },
      mediaInfo: mediaUpload ? {
        fileName: mediaUpload.fileName,
        fileType: mediaUpload.fileType,
        title: mediaUpload.title,
        fileUrl: mediaUpload.fileUrl
      } : null
    });

  } catch (error) {
    console.error('❌ Get upload progress error:', error);
    res.status(500).json({ success: false, error: 'Failed to get upload progress: ' + error.message });
  }
});

// ❌ POST /api/upload/cancel/:uploadId - Cancel upload
app.post('/api/upload/cancel/:uploadId', authenticateToken, async (req, res) => {
  try {
    const { uploadId } = req.params;

    const uploadProgress = await UploadProgress.findOne({ uploadId: uploadId });

    if (!uploadProgress) {
      return res.status(404).json({ success: false, error: 'Upload not found' });
    }

    // Verify ownership
    if (uploadProgress.userId.toString() !== req.user._id.toString()) {
      return res.status(403).json({ success: false, error: 'Access denied: you cannot cancel this upload' });
    }

    // Check if upload is already completed or cancelled
    if (uploadProgress.status === 'completed') {
      return res.status(400).json({ success: false, error: 'Cannot cancel a completed upload' });
    }

    if (uploadProgress.status === 'cancelled') {
      return res.status(400).json({ success: false, error: 'Upload is already cancelled' });
    }

    // Update upload progress status
    uploadProgress.status = 'cancelled';
    uploadProgress.lastUpdateTime = new Date();
    await uploadProgress.save();

    // Update media upload status
    const mediaUpload = await MediaUpload.findOne({ uploadId: uploadId });
    if (mediaUpload) {
      mediaUpload.status = 'cancelled';
      mediaUpload.cancelledAt = new Date();
      
      // Delete file if it exists
      if (fs.existsSync(mediaUpload.filePath)) {
        try {
          fs.unlinkSync(mediaUpload.filePath);
          console.log('✅ File deleted:', mediaUpload.filePath);
        } catch (unlinkError) {
          console.error('❌ Error deleting file:', unlinkError);
        }
      }

      await mediaUpload.save();
    }

    console.log('✅ Upload cancelled successfully:', uploadId);

    res.json({
      success: true,
      message: 'Upload cancelled successfully',
      uploadId: uploadId,
      status: 'cancelled'
    });

  } catch (error) {
    console.error('❌ Cancel upload error:', error);
    res.status(500).json({ success: false, error: 'Failed to cancel upload: ' + error.message });
  }
});

// =============================================
// 📖 STORY ENDPOINTS
// =============================================

// Create Story
app.post('/api/stories', authenticateToken, async (req, res) => {
  try {
    const { 
      type = 'text', 
      backgroundColor, 
      textItems, 
      stickers, 
      visibility = 'public', 
      specificViewers, 
      allowComments = true, 
      mediaUrl,
      thumbnailUrl
    } = req.body;

    console.log('📝 Creating story:', { type, userId: req.user._id });

    const expiresAt = new Date();
    expiresAt.setHours(expiresAt.getHours() + 24); // Expires in 24 hours

    const newStory = new Story({
      userId: req.user._id,
      type,
      backgroundColor,
      textItems,
      stickers,
      visibility,
      specificViewers,
      allowComments,
      mediaUrl,
      thumbnailUrl,
      expiresAt
    });

    await newStory.save();
    await newStory.populate('userId', 'username profilePicture userId');

    res.status(201).json({
      success: true,
      story: {
        id: newStory._id,
        ...newStory.toObject()
      }
    });
  } catch (error) {
    console.error('❌ Create story error:', error);
    res.status(500).json({ success: false, error: 'Failed to create story' });
  }
});

// Get Stories Feed (Friends + Self)
app.get('/api/stories/feed', authenticateToken, async (req, res) => {
  try {
    console.log('📱 Getting stories feed for:', req.user._id);

    // 1. Get friends
    const friendships = await FriendRequest.find({
      $or: [
        { fromUser: req.user._id, status: 'accepted' },
        { toUser: req.user._id, status: 'accepted' }
      ]
    });

    const friendIds = friendships.map(f => 
      f.fromUser.toString() === req.user._id.toString() ? f.toUser : f.fromUser
    );

    // Include self
    const targetIds = [...friendIds, req.user._id];

    // 2. Find active stories
    const stories = await Story.find({
      userId: { $in: targetIds },
      expiresAt: { $gt: new Date() }
    })
    .populate('userId', 'username profilePicture userId')
    .sort({ createdAt: 1 }) // Oldest first for stories usually, or grouped by user
    .lean();

    // Filter by visibility
    const visibleStories = stories.filter(story => {
      if (story.userId._id.toString() === req.user._id.toString()) return true;
      
      if (story.visibility === 'public') return true;
      if (story.visibility === 'friends') return true; // We already filtered by friendIds
      if (story.visibility === 'specific') {
        return story.specificViewers.some(id => id.toString() === req.user._id.toString());
      }
      return false;
    });

    // Format for response
    const formattedStories = visibleStories.map(story => ({
      id: story._id,
      type: story.type,
      mediaUrl: story.mediaUrl,
      thumbnailUrl: story.thumbnailUrl,
      backgroundColor: story.backgroundColor,
      textItems: story.textItems,
      stickers: story.stickers,
      createdAt: story.createdAt,
      expiresAt: story.expiresAt,
      isViewed: story.viewers && story.viewers.some(v => v.userId.toString() === req.user._id.toString()),
      user: {
        id: story.userId.userId || story.userId._id,
        username: story.userId.username,
        profilePicture: story.userId.profilePicture
      }
    }));

    res.json({ success: true, stories: formattedStories });
  } catch (error) {
    console.error('❌ Get stories feed error:', error);
    res.status(500).json({ success: false, error: 'Failed to get stories feed' });
  }
});

// Get My Stories
app.get('/api/stories/me', authenticateToken, async (req, res) => {
  try {
    const stories = await Story.find({
      userId: req.user._id,
      expiresAt: { $gt: new Date() }
    })
    .populate('userId', 'username profilePicture userId')
    .sort({ createdAt: -1 });

    const formattedStories = stories.map(story => ({
      id: story._id,
      type: story.type,
      mediaUrl: story.mediaUrl,
      thumbnailUrl: story.thumbnailUrl,
      backgroundColor: story.backgroundColor,
      textItems: story.textItems,
      stickers: story.stickers,
      createdAt: story.createdAt,
      expiresAt: story.expiresAt,
      viewersCount: story.viewers.length,
      user: {
        id: story.userId.userId || story.userId._id,
        username: story.userId.username,
        profilePicture: story.userId.profilePicture
      }
    }));

    res.json({ success: true, stories: formattedStories });
  } catch (error) {
    console.error('❌ Get my stories error:', error);
    res.status(500).json({ success: false, error: 'Failed to get my stories' });
  }
});

// Delete Story
app.delete('/api/stories/:id', authenticateToken, async (req, res) => {
  try {
    const story = await Story.findOne({ _id: req.params.id, userId: req.user._id });
    if (!story) return res.status(404).json({ success: false, error: 'Story not found' });

    await Story.deleteOne({ _id: req.params.id });
    res.json({ success: true, message: 'Story deleted' });
  } catch (error) {
    console.error('❌ Delete story error:', error);
    res.status(500).json({ success: false, error: 'Failed to delete story' });
  }
});

// View Story
app.post('/api/stories/:id/view', authenticateToken, async (req, res) => {
  try {
    await Story.findByIdAndUpdate(req.params.id, {
      $addToSet: { viewers: { userId: req.user._id, viewedAt: new Date() } }
    });
    res.json({ success: true });
  } catch (error) {
    console.error('❌ View story error:', error);
    res.status(500).json({ success: false, error: 'Failed to mark story as viewed' });
  }
});

// 🔥 Agora Token Generation Route
app.post('/api/agora/token', authenticateToken, async (req, res) => {
  try {
    const { channelName, uid = 0 } = req.body;
    
    console.log('🎥 Agora token request:', {
      userId: req.user._id,
      channelName: channelName,
      uid: uid
    });

    if (channelName) {
      const AGORA_APP_ID = process.env.AGORA_APP_ID || "5c57b43b4d544f51be764b8672ac06bf";
      const AGORA_APP_CERTIFICATE = process.env.AGORA_APP_CERTIFICATE;

      if (AGORA_APP_CERTIFICATE) {
        const { RtcTokenBuilder, RtcRole } = require('agora-token');

        const expirationTimeInSeconds = 3600;
        const currentTimestamp = Math.floor(Date.now() / 1000);
        const privilegeExpiredTs = currentTimestamp + expirationTimeInSeconds;

        const token = RtcTokenBuilder.buildTokenWithUid(
          AGORA_APP_ID,
          AGORA_APP_CERTIFICATE,
          channelName,
          uid,
          RtcRole.PUBLISHER,
          privilegeExpiredTs
        );

        console.log('✅ Agora token generated successfully for channel:', channelName);

        res.json({
          success: true,
          token: token,
          channelName: channelName,
          uid: uid,
          expiresIn: expirationTimeInSeconds,
          appId: AGORA_APP_ID
        });
      } else {
        console.error('❌ Agora certificate not configured');
        return res.status(500).json({ 
          success: false, 
          error: 'Agora service not configured' 
        });
      }
    } else {
      return res.status(400).json({ 
        success: false, 
        error: 'Channel name is required' 
      });
    }

  } catch (error) {
    console.error('❌ Agora token generation error:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to generate token: ' + error.message 
    });
  }
});

// 🔧 API สำหรับตรวจสอบสถานะแชททางการ
app.get('/api/admin/official-chats-status', authenticateToken, async (req, res) => {
  try {
    if (req.user.userType !== 'admin') {
      return res.status(403).json({
        success: false,
        error: 'Access denied. Admin only.'
      });
    }

    const systemUser = await User.findOne({ userType: 'system' });
    if (!systemUser) {
      return res.status(404).json({
        success: false,
        error: 'System user not found'
      });
    }

    const officialChats = await Chat.find({
      chatType: 'official',
      'participants': systemUser._id
    })
    .populate('participants', 'username email userType phone')
    .sort({ createdAt: 1 });

    const userChatCount = {};
    const duplicateUsers = [];

    officialChats.forEach(chat => {
      const normalUsers = chat.participants.filter(p => 
        p._id.toString() !== systemUser._id.toString() && p.userType !== 'system'
      );

      normalUsers.forEach(user => {
        const userId = user._id.toString();
        if (!userChatCount[userId]) {
          userChatCount[userId] = {
            user: user,
            chats: []
          };
        }
        userChatCount[userId].chats.push({
          chatId: chat._id,
          createdAt: chat.createdAt
        });
      });
    });

    Object.keys(userChatCount).forEach(userId => {
      if (userChatCount[userId].chats.length > 1) {
        duplicateUsers.push({
          user: userChatCount[userId].user,
          chatCount: userChatCount[userId].chats.length,
          chats: userChatCount[userId].chats
        });
      }
    });

    res.json({
      success: true,
      totalOfficialChats: officialChats.length,
      uniqueUsers: Object.keys(userChatCount).length,
      duplicateUsers: duplicateUsers.length,
      duplicateDetails: duplicateUsers,
      summary: {
        totalChats: officialChats.length,
        usersWithSingleChat: Object.keys(userChatCount).length - duplicateUsers.length,
        usersWithDuplicateChats: duplicateUsers.length
      }
    });

  } catch (error) {
    console.error('❌ Official chats status error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to get official chats status'
    });
  }
});

// 🔧 API สำหรับลบแชททางการที่ซ้ำกัน
app.delete('/api/admin/clean-duplicate-official-chats', authenticateToken, async (req, res) => {
  try {
    if (req.user.userType !== 'admin') {
      return res.status(403).json({
        success: false,
        error: 'Access denied. Admin only.'
      });
    }

    const systemUser = await User.findOne({ userType: 'system' });
    if (!systemUser) {
      return res.status(404).json({
        success: false,
        error: 'System user not found'
      });
    }

    console.log('🔍 Cleaning duplicate official chats...');

    const officialChats = await Chat.find({
      chatType: 'official',
      'participants': systemUser._id
    }).populate('participants');

    console.log(`📊 Found ${officialChats.length} official chats`);

    const userChatMap = new Map();
    const chatsToDelete = [];

    officialChats.forEach(chat => {
      const normalUsers = chat.participants.filter(p => 
        p._id.toString() !== systemUser._id.toString() && p.userType !== 'system'
      );

      normalUsers.forEach(user => {
        const userKey = user._id.toString();
        
        if (userChatMap.has(userKey)) {
          const existingChat = userChatMap.get(userKey);
          if (chat.createdAt > existingChat.createdAt) {
            chatsToDelete.push(existingChat._id);
            userChatMap.set(userKey, chat);
            console.log(`🔄 User ${user.username} has newer chat, keeping: ${chat._id}`);
          } else {
            chatsToDelete.push(chat._id);
            console.log(`🔄 User ${user.username} has older chat, deleting: ${chat._id}`);
          }
        } else {
          userChatMap.set(userKey, chat);
          console.log(`✅ User ${user.username} has single chat: ${chat._id}`);
        }
      });
    });

    console.log(`🗑️ Preparing to delete ${chatsToDelete.length} duplicate chats`);

    if (chatsToDelete.length > 0) {
      await Chat.deleteMany({ _id: { $in: chatsToDelete } });
      await Message.deleteMany({ chatId: { $in: chatsToDelete } });
      console.log(`✅ Deleted ${chatsToDelete.length} duplicate official chats`);
    }

    res.json({
      success: true,
      message: `Cleaned up ${chatsToDelete.length} duplicate official chats`,
      remainingChats: userChatMap.size,
      deletedChats: chatsToDelete.length
    });

  } catch (error) {
    console.error('❌ Clean duplicate official chats error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to clean duplicate official chats'
    });
  }
});

// 🔥 API ใหม่: บังคับลบแชททางการที่ซ้ำกันทั้งหมด
app.delete('/api/admin/force-clean-duplicates', authenticateToken, async (req, res) => {
  try {
    if (req.user.userType !== 'admin') {
      return res.status(403).json({
        success: false,
        error: 'Access denied. Admin only.'
      });
    }

    const systemUser = await User.findOne({ userType: 'system' });
    if (!systemUser) {
      return res.status(404).json({
        success: false,
        error: 'System user not found'
      });
    }

    console.log('💥 FORCE Cleaning all duplicate official chats...');

    const officialChats = await Chat.find({
      chatType: 'official',
      'participants': systemUser._id
    }).populate('participants');

    console.log(`📊 Found ${officialChats.length} official chats`);

    const userLatestChatMap = new Map();
    const allChatsToDelete = [];

    officialChats.forEach(chat => {
      const normalUsers = chat.participants.filter(p => 
        p._id.toString() !== systemUser._id.toString() && p.userType !== 'system'
      );

      normalUsers.forEach(user => {
        const userKey = user._id.toString();
        const existingChat = userLatestChatMap.get(userKey);
        
        if (!existingChat || chat.createdAt > existingChat.createdAt) {
          if (existingChat) {
            allChatsToDelete.push(existingChat._id);
          }
          userLatestChatMap.set(userKey, chat);
        } else {
          allChatsToDelete.push(chat._id);
        }
      });
    });

    console.log(`🗑️ Preparing to delete ${allChatsToDelete.length} duplicate chats`);

    if (allChatsToDelete.length > 0) {
      await Chat.deleteMany({ _id: { $in: allChatsToDelete } });
      await Message.deleteMany({ chatId: { $in: allChatsToDelete } });
      console.log(`✅ Force deleted ${allChatsToDelete.length} duplicate official chats`);
    }

    res.json({
      success: true,
      message: `Force cleaned ${allChatsToDelete.length} duplicate official chats`,
      remainingUsers: userLatestChatMap.size,
      deletedChats: allChatsToDelete.length,
      details: {
        totalUsers: userLatestChatMap.size,
        totalDeleted: allChatsToDelete.length,
        keptLatestChats: Array.from(userLatestChatMap.values()).map(chat => ({
          chatId: chat._id,
          user: chat.participants.find(p => p._id.toString() !== systemUser._id.toString())?.username
        }))
      }
    });

  } catch (error) {
    console.error('❌ Force clean duplicates error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to force clean duplicates'
    });
  }
});

// =============================================
// 🏥 HEALTH CHECK & ERROR HANDLING
// =============================================

// 🏥 Health Check
app.get('/api/health', (req, res) => {
  res.json({
    success: true,
    message: 'Server is healthy',
    timestamp: new Date().toISOString(),
    database: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
    security: 'Enhanced security enabled',
    environment: process.env.NODE_ENV || 'development',
    features: {
      wallet: true,
      identityVerification: true,
      bankServices: true,
      chat: true,
      friends: true,
      recovery: true,
      notifications: true // ✅ เพิ่มฟีเจอร์การแจ้งเตือน
    }
  });
});

// =============================================
// 📱 APP VERSION CHECK API
// =============================================

// 📱 ตรวจสอบเวอร์ชั่นแอป
app.get('/api/app/version', async (req, res) => {
  try {
    console.log('📱 App version check request');
    
    // ข้อมูลเวอร์ชั่นปัจจุบันในระบบ
    const currentVersion = "1.0.0"; // เวอร์ชั่นปัจจุบันของแอป
    const latestVersion = "1.1.0";  // เวอร์ชั่นล่าสุดที่ใช้แสดงในป๊อปอัพ
    
    // กำหนดว่ามีอัพเดทใหม่หรือไม่ (สามารถเปลี่ยนเป็น true เมื่อต้องการให้แสดงป๊อปอัพ)
    const updateAvailable = true; // เปลี่ยนเป็น false เมื่อไม่มีอัพเดท
    
    if (updateAvailable) {
      res.json({
        success: true,
        update_available: true,
        version_info: {
          version: latestVersion,
          release_date: new Date().toISOString(),
          features: [
            "เพิ่มระบบตรวจสอบเวอร์ชั่นอัตโนมัติ",
            "เพิ่มป๊อปอัพแจ้งเวอร์ชั่นใหม่",
            "ปรับปรุงระบบการแจ้งเตือน",
            "เพิ่มระบบนับถอยหลัง 3 วัน",
            "รองรับหลายภาษาในระบบอัพเดท",
            "ปรับปรุงความเสถียรของแอป",
            "แก้ไขข้อบกพร่องเล็กน้อย",
            "เพิ่มการรองรับธีมสีใหม่",
            "ปรับปรุงประสิทธิภาพการทำงาน"
          ],
          download_url: "https://github.com/your-username/chat-chat/releases/latest",
          minimum_required_version: "1.0.0",
          update_type: "optional", // หรือ "mandatory" ถ้าต้องการบังคับอัพเดท
          release_notes: {
            en: "New update with version checking system and improved features",
            th: "อัพเดทใหม่พร้อมระบบตรวจสอบเวอร์ชั่นและฟีเจอร์ที่ปรับปรุงแล้ว",
            zh: "新更新包含版本检查系统和改进的功能"
          }
        }
      });
    } else {
      res.json({
        success: true,
        update_available: false,
        message: "App is up to date",
        current_version: currentVersion,
        last_checked: new Date().toISOString()
      });
    }
    
    console.log('✅ Version check response sent:', { 
      update_available: updateAvailable,
      current_version: currentVersion,
      latest_version: latestVersion 
    });
    
  } catch (error) {
    console.error('❌ App version check error:', error);
    res.status(500).json({
      success: false,
      update_available: false,
      error: 'Failed to check app version'
    });
  }
});

// 📱 ฟังก์ชันสำหรับ Admin ในการตั้งค่าเวอร์ชั่น
app.post('/api/admin/app-version', authenticateToken, async (req, res) => {
  try {
    // ตรวจสอบว่าเป็น Admin หรือไม่
    if (req.user.userType !== 'admin') {
      return res.status(403).json({
        success: false,
        error: 'Access denied. Admin only.'
      });
    }

    const { 
      version, 
      update_available, 
      features, 
      download_url, 
      update_type,
      release_notes 
    } = req.body;

    console.log('👨‍💼 Admin updating app version settings:', {
      version,
      update_available,
      features_count: features?.length || 0,
      update_type
    });

    // ตรวจสอบข้อมูลที่จำเป็น
    if (!version || typeof update_available !== 'boolean') {
      return res.status(400).json({
        success: false,
        error: 'Version and update_available are required'
      });
    }

    // สร้างข้อมูลเวอร์ชั่นใหม่
    const versionInfo = {
      version: version,
      release_date: new Date().toISOString(),
      features: features || [
        "ปรับปรุงประสิทธิภาพการทำงาน",
        "แก้ไขข้อบกพร่อง",
        "เพิ่มความเสถียรของระบบ"
      ],
      download_url: download_url || "https://github.com/your-username/chat-chat/releases/latest",
      minimum_required_version: "1.0.0",
      update_type: update_type || "optional",
      release_notes: release_notes || {
        en: "App update",
        th: "อัพเดทแอปพลิเคชัน",
        zh: "应用程序更新"
      }
    };

    console.log('✅ App version settings updated by admin:', {
      admin: req.user.username,
      version: version,
      update_available: update_available
    });

    res.json({
      success: true,
      message: 'App version settings updated successfully',
      version_info: versionInfo,
      update_available: update_available,
      updated_by: req.user.username,
      updated_at: new Date().toISOString()
    });

  } catch (error) {
    console.error('❌ Admin update app version error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to update app version settings'
    });
  }
});

// 📱 ตรวจสอบสถานะเวอร์ชั่นของแอป
app.get('/api/app/version/status', async (req, res) => {
  try {
    console.log('📊 App version status check');
    
    // นับจำนวนผู้ใช้ที่อัพเดทแล้ว
    const thirtyDaysAgo = new Date();
    thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
    
    const totalUsers = await User.countDocuments({ isActive: true });
    const recentLogins = await User.countDocuments({ 
      isActive: true,
      lastLogin: { $gte: thirtyDaysAgo }
    });

    res.json({
      success: true,
      version_stats: {
        current_version: "1.0.0",
        latest_version: "1.1.0",
        total_active_users: totalUsers,
        recent_active_users: recentLogins,
        update_coverage_percentage: recentLogins > 0 ? Math.round((recentLogins / totalUsers) * 100) : 0,
        last_version_check: new Date().toISOString()
      },
      system_info: {
        server_time: new Date().toISOString(),
        uptime: process.uptime(),
        environment: process.env.NODE_ENV || 'development'
      }
    });

  } catch (error) {
    console.error('❌ App version status error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to get app version status'
    });
  }
});

// 📱 Webhook สำหรับรับการอัพเดทจาก GitHub (ถ้าต้องการ)
app.post('/api/webhooks/github/release', async (req, res) => {
  try {
    console.log('🔄 GitHub release webhook received');
    
    const { action, release } = req.body;
    
    if (action === 'released' && release) {
      console.log('🎉 New GitHub release detected:', {
        tag_name: release.tag_name,
        name: release.name,
        published_at: release.published_at
      });

      // บันทึกข้อมูลการปล่อยเวอร์ชั่นใหม่
      // สามารถบันทึกลงใน database ได้ถ้าต้องการเก็บประวัติ
      
      res.json({
        success: true,
        message: 'GitHub release webhook processed successfully',
        release: {
          version: release.tag_name,
          name: release.name,
          published_at: release.published_at,
          body: release.body ? release.body.substring(0, 200) + '...' : ''
        }
      });
    } else {
      res.json({
        success: true,
        message: 'Webhook received but no action taken'
      });
    }

  } catch (error) {
    console.error('❌ GitHub webhook error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to process GitHub webhook'
    });
  }
});

// 📊 Analytics Routes
app.get('/api/analytics/user', authenticateToken, async (req, res) => {
  // Mock analytics
  res.json({ 
    success: true, 
    stats: { messagesSent: 100, groupsJoined: 5, friendsCount: 10 } 
  });
});

app.get('/api/analytics/chat/:chatId', authenticateToken, async (req, res) => {
  // Mock analytics
  res.json({ 
    success: true, 
    stats: { totalMessages: 500, activeMembers: 10, lastActivity: new Date() } 
  });
});

// 🚨 Error Handling Middleware
app.use((error, req, res, next) => {
  console.error('❌ Unhandled error:', error);
  res.status(500).json({
    success: false,
    error: 'Internal server error'
  });
});

// 404 Handler
app.use('*', (req, res) => {
  res.status(404).json({
    success: false,
    error: 'Endpoint not found'
  });
});

// =============================================
// 🚀 START SERVER
// =============================================

const startServer = async () => {
  await initializeMourningSettings();
  await initializeBankServices();
  
  app.listen(PORT, '0.0.0.0', () => {  
    console.log('🚀 =================================');
    console.log('📡 Connect API Server Started!');
    console.log(`📍 Port: ${PORT}`);
    console.log(`🗄️  Database: Connected successfully`);
    console.log(`🌐 Environment: ${process.env.NODE_ENV || 'development'}`);
    console.log('🚀 =================================');
    console.log('🎯 Enhanced Security Features:');
    console.log('   • 🔐 Helmet.js Security Headers');
    console.log('   • 🛡️ Rate Limiting (100 requests/15min)');
    console.log('   • ✅ Input Validation & Sanitization');
    console.log('   • 🔒 Password Strength Enforcement');
    console.log('   • 🚫 Account Lockout Protection');
    console.log('   • 📧 Email Format Validation');
    console.log('   • 🗃️ Database Indexing for Performance');
    console.log('   • 🔐 Recovery ID System');
    console.log('🔥 NEW WALLET & IDENTITY SYSTEM:');
    console.log('   • 💰 Wallet & Coin Points Management');
    console.log('   • 🆔 Identity Verification System');
    console.log('   • 📸 Face Scan Process (6 Steps)');
    console.log('   • 💳 Bank Services Integration');
    console.log('   • 🏦 Multiple Bank Support (5 Banks)');
    console.log('   • 📊 Transaction & Reward History');
    console.log('📱 ENHANCED FEATURES:');
    console.log('   • 📞 Phone Number Support');
    console.log('   • 📋 PDPA Consent Tracking');
    console.log('   • 🔐 Enhanced Data Privacy');
    console.log('📨 NEW NOTIFICATION SYSTEM:');
    console.log('   • 🔔 Real-time Notifications');
    console.log('   • 💰 Wallet Transaction Alerts');
    console.log('   • 💬 Chat Message Notifications');
    console.log('   • 👥 Friend Request Alerts');
    console.log('   • 🆔 Identity Verification Updates');
    console.log('   • 🏦 Bank Service Notifications');
    console.log('   • 📊 Notification Statistics');
    console.log('   • 🔔 Push Notification Support');
    console.log('🚀 =================================');
  });
};

startServer();
