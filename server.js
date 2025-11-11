const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 30001;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';

// ✅ Security Middleware
app.use(helmet({
  crossOriginResourcePolicy: { policy: "cross-origin" }
}));

// ✅ Rate Limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: {
    success: false,
    error: 'Too many requests from this IP, please try again later.'
  }
});
app.use('/api/', limiter);

// Middleware
app.use(cors({
  origin: process.env.CORS_ORIGIN || '*',
  credentials: true
}));
app.use(express.json({ limit: '10mb' }));

// ✅ MongoDB Connection - ใช้ Environment Variable
mongoose.connect(process.env.MONGO_URL || process.env.MONGODB_URI || 'mongodb://localhost:27017/connect_app', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  ssl: true,
  tlsAllowInvalidCertificates: false,
  retryWrites: true,
  w: 'majority'
});

const db = mongoose.connection;
db.on('error', console.error.bind(console, 'MongoDB connection error:'));
db.once('open', () => {
  console.log('✅ Connected to MongoDB successfully');
  createSystemAccount();
});

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
  isActive: { type: Boolean, default: true }
});

// ✅ Add indexes for better performance
userSchema.index({ email: 1 });
userSchema.index({ userId: 1 });
userSchema.index({ createdAt: -1 });

const User = mongoose.model('User', userSchema);

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
  lastMessage: { type: String, default: '' },
  lastMessageTime: { type: Date, default: Date.now },
  unreadCount: { type: Map, of: Number, default: {} },
  isActive: { type: Boolean, default: true },
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

// ✅ Add indexes for chats
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

// ✅ Add indexes for messages
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

// ✅ Add indexes for friend requests
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

// 🔐 Encryption Utilities
const generateSalt = () => bcrypt.genSaltSync(12);
const hashPassword = (password, salt) => bcrypt.hashSync(password + salt, 12);
const verifyPassword = (password, hash, salt) => bcrypt.compareSync(password + salt, hash);
const generateAuthToken = (userId) => jwt.sign({ userId }, JWT_SECRET, { expiresIn: '30d' });

// 🔒 Auth Middleware
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

// 🔧 Utility Functions
const createSystemAccount = async () => {
  try {
    const existingSystem = await User.findOne({ userType: 'system', email: 'system@connect.app' });
    
    if (!existingSystem) {
      const salt = generateSalt();
      const systemUser = new User({
        username: 'Connect Support',
        email: 'system@connect.app',
        passwordHash: hashPassword('system_password_' + Date.now(), salt),
        passwordSalt: salt,
        userType: 'system',
        userId: 'support',
        settings: {
          language: 'en',
          theme: 'white'
        }
      });
      
      await systemUser.save();
      console.log('✅ System account created successfully');
    } else {
      console.log('✅ System account already exists');
    }
  } catch (error) {
    console.error('❌ Error creating system account:', error);
  }
};

const createOfficialChat = async (userId) => {
  try {
    const systemUser = await User.findOne({ userType: 'system' });
    
    if (!systemUser) {
      console.error('❌ System user not found');
      return;
    }

    const existingChat = await Chat.findOne({
      participants: { $all: [userId, systemUser._id] },
      chatType: 'official'
    });

    if (!existingChat) {
      const officialChat = new Chat({
        participants: [userId, systemUser._id],
        chatType: 'official',
        title: 'Connect Support',
        lastMessage: 'สวัสดี! ยินดีต้อนรับสู่ Connect App เราพร้อมให้ความช่วยเหลือเสมอ',
        lastMessageTime: new Date()
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
  }
};

// ✅ Input Validation Middleware
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
    .withMessage('Password must be at least 6 characters')
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

// 📱 API Routes

// 🏠 Home Route
app.get('/', (req, res) => {
  res.json({ 
    message: '🚀 Connect API Server is running!',
    version: '1.0.0',
    environment: process.env.NODE_ENV || 'development',
    security: 'Enhanced security enabled',
    endpoints: {
      settings: '/api/settings',
      mourning: '/api/mourning',
      register: '/api/register',
      login: '/api/login',
      profile: '/api/profile',
      chats: {
        list: '/api/chats',
        create: '/api/chats (POST)',
        private: '/api/chats/private/:friendId',
        messages: '/api/chats/:chatId/messages',
        sendMessage: '/api/chats/:chatId/messages (POST)',
        updateMessage: '/api/chats/:chatId/messages/:messageId (PUT)',
        deleteMessage: '/api/chats/:chatId/messages/:messageId/delete (PUT)',
        profile: '/api/chats/:chatId/profile'
      },
      users: {
        search: '/api/users/search',
        profile: '/api/users/:userId'
      },
      friends: {
        requests: '/api/friends/requests',
        list: '/api/friends',
        sendRequest: '/api/friends/request',
        accept: '/api/friends/requests/:requestId/accept',
        reject: '/api/friends/requests/:requestId/reject',
        remove: '/api/friends/:friendId',
        status: '/api/friends/status/:targetUserId'
      },
      profile: {
        picture: '/api/profile/picture',
        upload: '/api/profile/picture (POST)'
      },
      agora: {
        token: '/api/agora/token (POST)'
      }
    }
  });
});

// 👤 Get Contact Profile Picture for Chat (Protected)
app.get('/api/chats/:chatId/profile', authenticateToken, async (req, res) => {
  try {
    const { chatId } = req.params;
    
    console.log('📸 Fetching contact profile for chat:', chatId);

    const chat = await Chat.findOne({
      _id: chatId,
      participants: req.user._id,
      isActive: true
    })
    .populate('participants', 'username email userType profilePicture userId');

    if (!chat) {
      return res.status(404).json({
        success: false,
        error: 'Chat not found'
      });
    }

    // หาผู้ใช้ที่เป็นคู่สนทนา (ไม่ใช่ตัวเอง)
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
        userType: contactUser.userType
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

// 👤 Get My Profile Picture (Protected)
app.get('/api/profile/picture', authenticateToken, async (req, res) => {
  try {
    console.log('📸 Fetching my profile picture for user:', req.user._id);

    res.json({
      success: true,
      profilePicture: req.user.profilePicture || '',
      userInfo: {
        id: req.user.userId || req.user._id.toString(),
        username: req.user.username,
        email: req.user.email
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

// 💬 Create New Chat (Protected)
app.post('/api/chats', authenticateToken, async (req, res) => {
  try {
    const { participants } = req.body;
    const userId = req.user._id;

    console.log('💬 Creating new chat request:', { 
      userId: userId,
      userEmail: req.user.email,
      participants: participants 
    });

    if (!participants || !Array.isArray(participants) || participants.length === 0) {
      return res.status(400).json({
        success: false,
        error: 'Participants array is required'
      });
    }

    // ตรวจสอบว่าผู้ใช้ทั้งหมดมีอยู่จริง
    const users = await User.find({ 
      $or: [
        { userId: { $in: participants } },
        { _id: { $in: participants.filter(id => mongoose.Types.ObjectId.isValid(id)) } }
      ]
    }, 'userId _id username name email profilePicture');

    if (users.length !== participants.length) {
      const foundUserIds = users.map(u => u.userId || u._id.toString());
      const missingUsers = participants.filter(p => !foundUserIds.includes(p));
      console.log('❌ Some users not found:', missingUsers);
      return res.status(400).json({
        success: false,
        error: `Users not found: ${missingUsers.join(', ')}`
      });
    }

    // แปลง participant IDs เป็น ObjectId
    const participantIds = users.map(user => user._id);
    
    // รวมผู้ใช้ปัจจุบันเข้าไปใน participants
    const allParticipants = [userId, ...participantIds];
    const uniqueParticipants = [...new Set(allParticipants.map(id => id.toString()))].map(id => new mongoose.Types.ObjectId(id));

    // ตรวจสอบว่ามีแชทกับผู้ใช้เหล่านี้อยู่แล้วหรือไม่
    const existingChat = await Chat.findOne({
      participants: { $all: uniqueParticipants },
      $expr: { $eq: [{ $size: "$participants" }, uniqueParticipants.length] }
    }).populate('participants', 'userId username name email profilePicture');

    if (existingChat) {
      console.log('✅ Using existing chat:', existingChat._id);
      return res.json({
        success: true,
        chat: {
          id: existingChat._id,
          _id: existingChat._id,
          participants: existingChat.participants,
          chatType: existingChat.chatType,
          title: existingChat.title,
          createdAt: existingChat.createdAt,
          lastMessage: existingChat.lastMessage,
          lastMessageTime: existingChat.lastMessageTime
        },
        message: 'Chat already exists'
      });
    }

    // สร้างชื่อแชทจากชื่อผู้ใช้
    const otherUsers = users.filter(user => user._id.toString() !== userId.toString());
    const chatTitle = otherUsers.map(user => user.username).join(', ');

    // สร้างแชทใหม่
    const newChat = new Chat({
      participants: uniqueParticipants,
      chatType: 'direct',
      title: chatTitle,
      lastMessage: 'เริ่มการสนทนา',
      lastMessageTime: new Date(),
      createdBy: userId,
      createdAt: new Date(),
      updatedAt: new Date()
    });

    await newChat.save();

    // Populate ข้อมูลผู้ใช้
    await newChat.populate('participants', 'userId username name email profilePicture');

    console.log('✅ New chat created successfully:', {
      chatId: newChat._id,
      participants: newChat.participants.map(p => p.username),
      createdBy: req.user.username
    });

    // สร้างข้อความเริ่มต้น
    const welcomeMessage = new Message({
      chatId: newChat._id,
      senderId: userId,
      messageType: 'system',
      content: 'เริ่มการสนทนา',
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
        title: newChat.title,
        createdAt: newChat.createdAt,
        lastMessage: newChat.lastMessage,
        lastMessageTime: newChat.lastMessageTime
      },
      message: 'Chat created successfully'
    });

  } catch (error) {
    console.error('❌ Error creating chat:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to create chat: ' + error.message
    });
  }
});

// 💬 Get Private Chat with Friend (Protected)
app.get('/api/chats/private/:friendId', authenticateToken, async (req, res) => {
  try {
    const { friendId } = req.params;
    const userId = req.user._id;

    console.log('🔍 Finding private chat with friend:', { 
      userId: userId,
      friendId: friendId 
    });

    // ค้นหาผู้ใช้ที่เป็นเพื่อน
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

    // ค้นหาแชทส่วนตัวที่มีอยู่
    const chat = await Chat.findOne({
      participants: { $all: [userId, friendUser._id] },
      chatType: 'direct'
    }).populate('participants', 'userId username name email profilePicture');

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

// 👥 Search Users (Protected)
app.get('/api/users/search', authenticateToken, async (req, res) => {
  try {
    const { query } = req.query;

    console.log('🔍 User search request:', {
      userId: req.user._id,
      query: query
    });

    if (!query || query.trim().length < 2) {
      return res.status(400).json({
        success: false,
        error: 'Search query must be at least 2 characters'
      });
    }

    const searchTerm = query.trim().toLowerCase();

    const users = await User.find({
      _id: { $ne: req.user._id },
      $or: [
        { username: { $regex: searchTerm, $options: 'i' } },
        { email: { $regex: searchTerm, $options: 'i' } },
        { userId: { $regex: searchTerm, $options: 'i' } }
      ],
      isActive: true
    })
    .select('username email userId profilePicture userType lastLogin createdAt')
    .limit(20);

    console.log('✅ Found', users.length, 'users for query:', searchTerm);

    const formattedUsers = users.map(user => ({
      id: user.userId || user._id.toString(),
      name: user.username,
      email: user.email,
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

// 👥 Send Friend Request (Protected) - แก้ไขเวอร์ชัน
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

    // Try to find user by userId first
    let targetUser = await User.findOne({ 
      userId: targetUserId,
      isActive: true 
    });
    
    console.log('🔍 Target user search by userId:', {
      targetUserId: targetUserId,
      found: !!targetUser,
      targetUser: targetUser ? {
        id: targetUser._id,
        userId: targetUser.userId,
        username: targetUser.username
      } : null
    });

    // If not found by userId, try by _id
    if (!targetUser) {
      try {
        if (mongoose.Types.ObjectId.isValid(targetUserId)) {
          targetUser = await User.findOne({ 
            _id: targetUserId,
            isActive: true 
          });
          console.log('🔍 Target user search by _id:', {
            targetUserId: targetUserId,
            found: !!targetUser
          });
        }
      } catch (error) {
        console.log('❌ Error searching by _id:', error.message);
      }
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

    // Check if sending to self
    if (targetUser._id.toString() === req.user._id.toString()) {
      console.log('❌ Cannot send friend request to yourself');
      return res.status(400).json({
        success: false,
        error: 'Cannot send friend request to yourself'
      });
    }

    // Check for existing pending request
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

    // Check if they are already friends
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

    // Create new friend request
    const friendRequest = new FriendRequest({
      fromUser: req.user._id,
      toUser: targetUser._id,
      status: 'pending'
    });

    console.log('💾 Saving friend request...');
    await friendRequest.save();
    console.log('✅ Friend request saved successfully:', friendRequest._id);

    console.log('🎉 Friend request sent successfully!');

    res.json({
      success: true,
      message: 'Friend request sent successfully',
      targetUser: {
        id: targetUser.userId || targetUser._id.toString(),
        name: targetUser.username,
        email: targetUser.email
      },
      requestId: friendRequest._id
    });

  } catch (error) {
    console.error('❌ Send friend request error:', error);
    console.error('❌ Error details:', {
      message: error.message,
      stack: error.stack
    });
    res.status(500).json({
      success: false,
      error: 'Failed to send friend request: ' + error.message
    });
  }
});

// 👥 Get User Profile by ID (Protected)
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
    .select('username email userId profilePicture userType lastLogin createdAt');

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

// 👥 Friend Management API Routes

// 📩 Get Friend Requests (Protected)
app.get('/api/friends/requests', authenticateToken, async (req, res) => {
  try {
    console.log('📩 Getting friend requests for user:', req.user._id);

    const friendRequests = await FriendRequest.find({
      toUser: req.user._id,
      status: 'pending'
    })
    .populate('fromUser', 'username email userId profilePicture userType lastLogin')
    .sort({ createdAt: -1 });

    const formattedRequests = friendRequests.map(request => ({
      id: request._id,
      sender: {
        id: request.fromUser.userId || request.fromUser._id.toString(),
        name: request.fromUser.username,
        email: request.fromUser.email,
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

// 👫 Get Friends List (Protected)
app.get('/api/friends', authenticateToken, async (req, res) => {
  try {
    console.log('👫 Getting friends list for user:', req.user._id);

    const friendRequests = await FriendRequest.find({
      $or: [
        { fromUser: req.user._id, status: 'accepted' },
        { toUser: req.user._id, status: 'accepted' }
      ]
    })
    .populate('fromUser', 'username email userId profilePicture userType lastLogin createdAt')
    .populate('toUser', 'username email userId profilePicture userType lastLogin createdAt')
    .sort({ updatedAt: -1 });

    const friends = friendRequests.map(request => {
      const isFromUser = request.fromUser._id.toString() === req.user._id.toString();
      const friendUser = isFromUser ? request.toUser : request.fromUser;
      
      return {
        id: friendUser.userId || friendUser._id.toString(),
        name: friendUser.username,
        email: friendUser.email,
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

// ✅ Accept Friend Request (Protected)
app.post('/api/friends/requests/:requestId/accept', authenticateToken, async (req, res) => {
  try {
    const { requestId } = req.params;

    console.log('✅ Accepting friend request:', requestId);

    const friendRequest = await FriendRequest.findOne({
      _id: requestId,
      toUser: req.user._id,
      status: 'pending'
    })
    .populate('fromUser', 'username email userId')
    .populate('toUser', 'username email userId');

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

    res.json({
      success: true,
      message: 'Friend request accepted successfully',
      friend: {
        id: friendRequest.fromUser.userId || friendRequest.fromUser._id.toString(),
        name: friendRequest.fromUser.username,
        email: friendRequest.fromUser.email
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

// ❌ Reject Friend Request (Protected)
app.post('/api/friends/requests/:requestId/reject', authenticateToken, async (req, res) => {
  try {
    const { requestId } = req.params;

    console.log('❌ Rejecting friend request:', requestId);

    const friendRequest = await FriendRequest.findOne({
      _id: requestId,
      toUser: req.user._id,
      status: 'pending'
    })
    .populate('fromUser', 'username email userId');

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

// 🗑️ Remove Friend (Protected)
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
        name: friendUser.username
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

// 🔍 Check Friendship Status (Protected)
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
        name: targetUser.username
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

// 👤 User Registration (✅ Enhanced Security)
app.post('/api/register', validateRegistration, async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        error: errors.array()[0].msg
      });
    }

    const { username, email, password, language = 'en', theme = 'white' } = req.body;

    console.log('👤 User registration attempt:', { username, email });

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({
        success: false,
        error: 'Email already registered'
      });
    }

    const salt = generateSalt();
    const passwordHash = hashPassword(password, salt);
    const authToken = generateAuthToken(new mongoose.Types.ObjectId());

    const newUser = new User({
      username: username.trim(),
      email: email.trim().toLowerCase(),
      passwordHash,
      passwordSalt: salt,
      authToken,
      tokenExpiry: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
      settings: { 
        language: language,
        theme: theme
      }
    });

    await newUser.save();

    await createOfficialChat(newUser._id);

    console.log('✅ User registered successfully:', newUser._id);

    res.status(201).json({
      success: true,
      message: 'User registered successfully',
      user: {
        id: newUser._id,
        username: newUser.username,
        email: newUser.email,
        settings: newUser.settings
      },
      authToken
    });

  } catch (error) {
    console.error('❌ Registration error:', error);
    res.status(500).json({
      success: false,
      error: 'Registration failed'
    });
  }
});

// 🔐 User Login (✅ Enhanced Security)
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
    if (!user) {
      console.log('❌ User not found:', email);
      return res.status(400).json({
        success: false,
        error: 'Invalid email or password'
      });
    }

    // ✅ Rate limiting for failed attempts
    if (user.failedLoginAttempts >= 5) {
      const lockoutTime = 15 * 60 * 1000; // 15 minutes
      const timeSinceLastAttempt = Date.now() - user.lastLogin.getTime();
      
      if (timeSinceLastAttempt < lockoutTime) {
        return res.status(429).json({
          success: false,
          error: 'Account temporarily locked due to too many failed attempts'
        });
      } else {
        // Reset failed attempts after lockout period
        user.failedLoginAttempts = 0;
      }
    }

    const isValid = verifyPassword(password, user.passwordHash, user.passwordSalt);
    if (!isValid) {
      user.failedLoginAttempts += 1;
      user.lastLogin = new Date();
      await user.save();
      
      console.log('❌ Invalid password for user:', email);
      return res.status(400).json({
        success: false,
        error: 'Invalid email or password'
      });
    }

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
        settings: user.settings,
        profilePicture: user.profilePicture,
        userId: user.userId
      },
      authToken
    });

  } catch (error) {
    console.error('❌ Login error:', error);
    res.status(500).json({
      success: false,
      error: 'Login failed'
    });
  }
});

// 👤 Get User Profile (Protected)
app.get('/api/profile', authenticateToken, async (req, res) => {
  try {
    console.log('📋 Profile request for user:', req.user._id);
    
    res.json({
      success: true,
      user: {
        id: req.user._id,
        username: req.user.username,
        email: req.user.email,
        settings: req.user.settings,
        profilePicture: req.user.profilePicture,
        userId: req.user.userId,
        lastLogin: req.user.lastLogin
      }
    });
  } catch (error) {
    console.error('❌ Profile error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to get profile'
    });
  }
});

// 👤 Update User Profile (Protected)
app.put('/api/profile', authenticateToken, [
  body('username')
    .isLength({ min: 3, max: 30 })
    .withMessage('Username must be between 3-30 characters')
    .trim()
    .escape()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        error: errors.array()[0].msg
      });
    }

    const { username, profilePicture } = req.body;

    console.log('👤 Updating profile for user:', req.user._id);

    if (username !== req.user.username) {
      const existingUser = await User.findOne({ 
        _id: { $ne: req.user._id },
        username: username.trim()
      });

      if (existingUser) {
        return res.status(400).json({
          success: false,
          error: 'Username already taken'
        });
      }
    }

    req.user.username = username.trim();
    
    if (profilePicture) {
      req.user.profilePicture = profilePicture;
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
        profilePicture: req.user.profilePicture,
        settings: req.user.settings
      }
    });

  } catch (error) {
    console.error('❌ Update profile error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to update profile'
    });
  }
});

// ⚙️ Update User Settings (Protected)
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

// 🆔 Change User ID (Protected)
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

    if (existingUser) {
      return res.status(400).json({
        success: false,
        error: 'User ID already taken'
      });
    }

    const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
    if (req.user.lastUserIdChange && req.user.lastUserIdChange > thirtyDaysAgo) {
      const daysLeft = Math.ceil((req.user.lastUserIdChange.getTime() - thirtyDaysAgo.getTime()) / (24 * 60 * 60 * 1000));
      return res.status(400).json({
        success: false,
        error: `You can change User ID again in ${daysLeft} days`
      });
    }

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

  } catch (error) {
    console.error('❌ Change User ID error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to change User ID'
    });
  }
});

// 📧 Change Email (Protected)
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

    if (existingUser) {
      return res.status(400).json({
        success: false,
        error: 'Email already registered'
      });
    }

    if (req.user.email === newEmail.toLowerCase().trim()) {
      return res.status(400).json({
        success: false,
        error: 'This is already your current email'
      });
    }
    
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

  } catch (error) {
    console.error('❌ Change email error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to change email'
    });
  }
});

// ⏰ Get ID Change Status (Protected)
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

// 🖼️ Upload Profile Picture (Protected)
app.post('/api/profile/picture', authenticateToken, async (req, res) => {
  try {
    const { imageData } = req.body;

    console.log('🖼️ Profile picture upload for user:', req.user._id);

    if (!imageData) {
      return res.status(400).json({
        success: false,
        error: 'Image data is required'
      });
    }

    if (!imageData.startsWith('data:image/')) {
      return res.status(400).json({
        success: false,
        error: 'Invalid image format. Please use base64 encoded image.'
      });
    }

    const base64Data = imageData.replace(/^data:image\/\w+;base64,/, '');
    const buffer = Buffer.from(base64Data, 'base64');
    
    if (buffer.length > 2 * 1024 * 1024) {
      return res.status(400).json({
        success: false,
        error: 'Image size too large. Maximum 2MB allowed.'
      });
    }

    req.user.profilePicture = imageData;
    req.user.updatedAt = new Date();

    await req.user.save();

    console.log('✅ Profile picture uploaded successfully');

    res.json({
      success: true,
      message: 'Profile picture uploaded successfully',
      profilePicture: imageData
    });

  } catch (error) {
    console.error('❌ Upload profile picture error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to upload profile picture'
    });
  }
});

// 💬 Get User Chats (Protected)
app.get('/api/chats', authenticateToken, async (req, res) => {
  try {
    console.log('💬 Fetching chats for user:', req.user._id);

    const chats = await Chat.find({
      participants: req.user._id,
      isActive: true
    })
    .populate('participants', 'username email userType profilePicture userId')
    .sort({ lastMessageTime: -1 });

    const formattedChats = chats.map(chat => {
      const otherParticipant = chat.participants.find(
        p => p._id.toString() !== req.user._id.toString()
      );
      
      return {
        id: chat._id,
        name: otherParticipant ? otherParticipant.username : chat.title,
        lastMessage: chat.lastMessage,
        timestamp: chat.lastMessageTime,
        unreadCount: chat.unreadCount.get(req.user._id.toString()) || 0,
        isOnline: otherParticipant ? (otherParticipant.userType === 'system' ? true : false) : false,
        avatar: otherParticipant ? '👤' : '💼',
        chatType: chat.chatType,
        isOfficial: chat.chatType === 'official',
        profilePicture: otherParticipant?.profilePicture || null,
        contactId: otherParticipant?.userId || otherParticipant?._id.toString()
      };
    });

    console.log('✅ Found', formattedChats.length, 'chats for user');

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

// 💬 Get Chat Messages (Protected)
app.get('/api/chats/:chatId/messages', authenticateToken, async (req, res) => {
  try {
    const { chatId } = req.params;
    
    console.log('📨 Fetching messages for chat:', chatId);

    const chat = await Chat.findOne({
      _id: chatId,
      participants: req.user._id
    });

    if (!chat) {
      return res.status(404).json({
        success: false,
        error: 'Chat not found'
      });
    }

    const messages = await Message.find({ 
      chatId,
      isDeleted: false
    })
      .populate('senderId', 'username userType profilePicture userId')
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
        senderId: msg.senderId.userId || msg.senderId._id.toString()
      };
    });

    console.log('✅ Found', formattedMessages.length, 'messages for chat');

    res.json({
      success: true,
      messages: formattedMessages
    });

  } catch (error) {
    console.error('❌ Get messages error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch messages'
    });
  }
});

// 💬 Send Message (Protected)
app.post('/api/chats/:chatId/messages', authenticateToken, async (req, res) => {
  try {
    const { chatId } = req.params;
    const { content, messageType = 'text' } = req.body;

    console.log('📤 Sending message to chat:', chatId);

    const chat = await Chat.findOne({
      _id: chatId,
      participants: req.user._id
    });

    if (!chat) {
      return res.status(404).json({
        success: false,
        error: 'Chat not found'
      });
    }

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
        profilePicture: req.user.profilePicture
      }
    });

  } catch (error) {
    console.error('❌ Send message error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to send message'
    });
  }
});

// 🔥 Soft Delete Message (Protected)
app.put('/api/chats/:chatId/messages/:messageId/delete', authenticateToken, async (req, res) => {
  try {
    const { chatId, messageId } = req.params;
    
    console.log('🗑️ Soft deleting message:', messageId, 'from chat:', chatId);

    const chat = await Chat.findOne({
      _id: chatId,
      participants: req.user._id
    });

    if (!chat) {
      return res.status(404).json({
        success: false,
        error: 'Chat not found'
      });
    }

    const message = await Message.findOne({
      _id: messageId,
      chatId: chatId
    });

    if (!message) {
      return res.status(404).json({
        success: false,
        error: 'Message not found'
      });
    }

    if (message.senderId.toString() !== req.user._id.toString()) {
      return res.status(403).json({
        success: false,
        error: 'You can only delete your own messages'
      });
    }

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

  } catch (error) {
    console.error('❌ Soft delete message error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to delete message'
    });
  }
});

// 🔥 Update Message (Protected)
app.put('/api/chats/:chatId/messages/:messageId', authenticateToken, async (req, res) => {
  try {
    const { chatId, messageId } = req.params;
    const { content } = req.body;
    
    console.log('✏️ Updating message:', messageId, 'from chat:', chatId);

    const chat = await Chat.findOne({
      _id: chatId,
      participants: req.user._id
    });

    if (!chat) {
      return res.status(404).json({
        success: false,
        error: 'Chat not found'
      });
    }

    const message = await Message.findOne({
      _id: messageId,
      chatId: chatId
    });

    if (!message) {
      return res.status(404).json({
        success: false,
        error: 'Message not found'
      });
    }

    if (message.senderId.toString() !== req.user._id.toString()) {
      return res.status(403).json({
        success: false,
        error: 'You can only edit your own messages'
      });
    }

    if (message.isDeleted) {
      return res.status(400).json({
        success: false,
        error: 'Cannot edit deleted message'
      });
    }

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

  } catch (error) {
    console.error('❌ Update message error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to update message'
    });
  }
});

// 🔥 เพิ่ม Agora Token Generation Route
app.post('/api/agora/token', authenticateToken, async (req, res) => {
  try {
    const { channelName, uid = 0 } = req.body;
    
    console.log('🎥 Agora token request:', {
      userId: req.user._id,
      channelName: channelName,
      uid: uid
    });

    if (!channelName) {
      return res.status(400).json({ 
        success: false, 
        error: 'Channel name is required' 
      });
    }

    // 🔑 Agora Configuration (เพิ่มใน .env ของคุณ)
    const AGORA_APP_ID = process.env.AGORA_APP_ID || "5c57b43b4d544f51be764b8672ac06bf";
    const AGORA_APP_CERTIFICATE = process.env.AGORA_APP_CERTIFICATE;

    if (!AGORA_APP_CERTIFICATE) {
      console.error('❌ Agora certificate not configured');
      return res.status(500).json({ 
        success: false, 
        error: 'Agora service not configured' 
      });
    }

    // ต้องติดตั้ง package ก่อน: npm install agora-token
    const { RtcTokenBuilder, RtcRole } = require('agora-token');

    // คำนวณ expiration time (1 ชั่วโมง)
    const expirationTimeInSeconds = 3600;
    const currentTimestamp = Math.floor(Date.now() / 1000);
    const privilegeExpiredTs = currentTimestamp + expirationTimeInSeconds;

    // สร้าง token
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

  } catch (error) {
    console.error('❌ Agora token generation error:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to generate token: ' + error.message 
    });
  }
});

// 🏥 Health Check
app.get('/api/health', (req, res) => {
  res.json({
    success: true,
    message: 'Server is healthy',
    timestamp: new Date().toISOString(),
    database: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
    security: 'Enhanced security enabled',
    environment: process.env.NODE_ENV || 'development'
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

// เริ่มต้นเซิร์ฟเวอร์
const startServer = async () => {
  await initializeMourningSettings();
  
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
    console.log('🚀 =================================');
  });
};

startServer();