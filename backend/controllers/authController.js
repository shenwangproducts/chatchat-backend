const User = require('../models/User');
const Wallet = require('../models/Wallet');
const Chat = require('../models/Chat');
const Message = require('../models/Message');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { validationResult } = require('express-validator');
const mongoose = require('mongoose');

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';

// --- Helper Functions ---
const generateSalt = () => bcrypt.genSaltSync(12);
const hashPassword = (password, salt) => bcrypt.hashSync(password + salt, 12);
const verifyPassword = (password, hash, salt) => bcrypt.compareSync(password + salt, hash);
const generateAuthToken = (userId) => jwt.sign({ userId }, JWT_SECRET, { expiresIn: '30d' });

const createUserWallet = async (userId) => {
  const existingWallet = await Wallet.findOne({ userId });
  if (!existingWallet) {
    const newWallet = new Wallet({ userId: userId, balance: 0.0, coinPoints: 0, currency: 'THB' });
    await newWallet.save();
    return newWallet;
  }
  return existingWallet;
};

const createOfficialChat = async (userId) => {
  const systemUser = await User.findOne({ userType: 'system' });
  if (!systemUser) return;

  const existingChat = await Chat.findOne({ participants: { $all: [userId, systemUser._id] }, chatType: 'official' });
  if (!existingChat) {
    const officialChat = new Chat({
      participants: [userId, systemUser._id],
      chatType: 'official',
      title: 'Connect Support',
      lastMessage: 'สวัสดี! ยินดีต้อนรับสู่ Connect App เราพร้อมให้ความช่วยเหลือเสมอ',
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
  }
};
// ------------------------

exports.register = async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ success: false, error: errors.array()[0].msg });

    const { username, email, password, phone, language = 'en', theme = 'white', pdpa_consent, consent_timestamp } = req.body;

    if (!pdpa_consent) return res.status(400).json({ success: false, error: 'PDPA consent is required' });

    const existingUser = await User.findOne({ email: email.trim().toLowerCase() });
    if (existingUser) return res.status(400).json({ success: false, error: 'Email already registered' });

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
      settings: { language, theme },
      pdpaConsent: pdpa_consent,
      consentTimestamp: consent_timestamp || new Date().toISOString()
    });

    await newUser.save();
    await createUserWallet(newUser._id);
    await createOfficialChat(newUser._id);

    res.status(201).json({
      success: true,
      message: 'User registered successfully',
      user: { id: newUser._id, username: newUser.username, email: newUser.email, settings: newUser.settings },
      authToken
    });
  } catch (error) {
    console.error('❌ Registration error:', error);
    res.status(500).json({ success: false, error: 'Registration failed' });
  }
};

exports.login = async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ success: false, error: errors.array()[0].msg });

    const { email, password } = req.body;
    const user = await User.findOne({ email: email.trim().toLowerCase() });

    if (!user) return res.status(400).json({ success: false, error: 'Invalid email or password' });

    if (user.failedLoginAttempts >= 5) {
      const timeSinceLastAttempt = Date.now() - (user.lastLogin?.getTime() || 0);
      if (timeSinceLastAttempt < 15 * 60 * 1000) return res.status(429).json({ success: false, error: 'Account temporarily locked' });
      user.failedLoginAttempts = 0;
    }

    if (!verifyPassword(password, user.passwordHash, user.passwordSalt)) {
      user.failedLoginAttempts += 1;
      user.lastLogin = new Date();
      await user.save();
      return res.status(400).json({ success: false, error: 'Invalid email or password' });
    }

    const authToken = generateAuthToken(user._id);
    user.authToken = authToken;
    user.tokenExpiry = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
    user.lastLogin = new Date();
    user.failedLoginAttempts = 0;
    await user.save();

    await createOfficialChat(user._id);

    res.json({
      success: true,
      message: 'Login successful',
      user: { id: user._id, username: user.username, email: user.email, settings: user.settings, profilePicture: user.profilePicture },
      authToken
    });
  } catch (error) {
    console.error('❌ Login error:', error);
    res.status(500).json({ success: false, error: 'Login failed' });
  }
};

exports.logout = async (req, res) => {
  try {
    req.user.authToken = null;
    req.user.tokenExpiry = null;
    await req.user.save();
    res.json({ success: true, message: 'Logged out successfully' });
  } catch (error) {
    console.error('❌ Logout error:', error);
    res.status(500).json({ success: false, error: 'Logout failed' });
  }
};