const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const OAuthApp = require('../models/OAuthApp');
const OAuthToken = require('../models/OAuthToken');
const User = require('../models/User');
const authMiddleware = require('../middlewares/auth'); // นำ Middleware มาใช้

// 1. รับการกด "อนุญาต" หรือ "ปฏิเสธ" จากแอป ChatChat
router.post('/authorize', authMiddleware, async (req, res) => {
  try {
    const { client_id, redirect_uri, state, scope, approved } = req.body;
    const userId = req.user._id; // ดึงจาก authMiddleware

    // เช็คว่าแอป (client_id) นี้มีจริงไหม
    const app = await OAuthApp.findOne({ clientId: client_id });
    if (!app) {
      return res.status(400).json({ success: false, error: 'ไม่พบแอปพลิเคชัน (Invalid Client ID)' });
    }

    // ถ้าผู้ใช้กด "ปฏิเสธ"
    if (!approved) {
      return res.json({ 
        success: true, 
        redirect_url: `${redirect_uri}?error=access_denied&state=${state}` 
      });
    }

    // ถ้ากดอนุญาต ให้สร้าง Authorization Code ชั่วคราว (อายุ 5 นาที)
    const authorizationCode = crypto.randomBytes(20).toString('hex');
    const expiresAt = new Date(Date.now() + 5 * 60000); // หมดอายุใน 5 นาที

    await OAuthToken.create({
      authorizationCode,
      userId,
      clientId: client_id,
      scope,
      expiresAt
    });

    // ส่ง URL ให้ Flutter เด้งกลับไปหาแอปที่ 3 พร้อม Code
    return res.json({
      success: true,
      redirect_url: `${redirect_uri}?code=${authorizationCode}&state=${state}`
    });

  } catch (error) {
    console.error('OAuth Authorize Error:', error);
    res.status(500).json({ success: false, error: 'Internal Server Error' });
  }
});

// 2. แอปที่ 3 (Third-party) เอา Code มาแลกเป็น Access Token
router.post('/token', async (req, res) => {
  try {
    const { client_id, client_secret, code, grant_type, redirect_uri } = req.body;

    if (grant_type !== 'authorization_code') {
      return res.status(400).json({ error: 'unsupported_grant_type' });
    }

    // เช็คความถูกต้องของแอปที่ 3 (App Authentication)
    const app = await OAuthApp.findOne({ clientId: client_id, clientSecret: client_secret });
    if (!app) {
      return res.status(401).json({ error: 'invalid_client' });
    }

    // เช็ค Authorization Code
    const tokenRecord = await OAuthToken.findOne({ authorizationCode: code, clientId: client_id });
    if (!tokenRecord || tokenRecord.expiresAt < new Date()) {
      return res.status(400).json({ error: 'invalid_grant', error_description: 'Code is invalid or expired' });
    }

    // สร้าง Access Token ใหม่ (อายุ 30 วัน)
    const accessToken = crypto.randomBytes(40).toString('hex');
    
    // อัปเดต Database: ลบ Code ทิ้ง และใส่ Access Token เข้าไปแทน
    tokenRecord.authorizationCode = undefined;
    tokenRecord.accessToken = accessToken;
    tokenRecord.expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000); // 30 วัน
    await tokenRecord.save();

    // ตอบกลับตามมาตรฐาน OAuth 2.0
    return res.json({
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: 30 * 24 * 60 * 60 // 30 วัน เป็นวินาที
    });

  } catch (error) {
    console.error('OAuth Token Error:', error);
    res.status(500).json({ error: 'server_error' });
  }
});

// 3. แอปที่ 3 นำ Access Token มาดึงข้อมูลผู้ใช้
router.get('/userinfo', async (req, res) => {
  try {
    // ดึง token จาก Header: "Authorization: Bearer <token>"
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const accessToken = authHeader.split(' ')[1];
    const tokenRecord = await OAuthToken.findOne({ accessToken });

    if (!tokenRecord || tokenRecord.expiresAt < new Date()) {
      return res.status(401).json({ error: 'invalid_token' });
    }

    // ดึงข้อมูลผู้ใช้จากฐานข้อมูล
    const user = await User.findById(tokenRecord.userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // ตอบกลับข้อมูลตามที่ขอ (ห้ามส่ง Password ไปเด็ดขาด)
    return res.json({
      sub: user._id.toString(), // มาตรฐาน OAuth ใช้ 'sub' สำหรับ ID ผู้ใช้
      name: user.username,
      email: user.email,
      picture: user.profilePicture || ''
    });

  } catch (error) {
    console.error('OAuth UserInfo Error:', error);
    res.status(500).json({ error: 'server_error' });
  }
});

module.exports = router;