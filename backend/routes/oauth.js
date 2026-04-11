const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const OAuthApp = require('../models/OAuthApp');
const OAuthToken = require('../models/OAuthToken');
const User = require('../models/User');
const authMiddleware = require('../middlewares/auth'); // นำ Middleware มาใช้

// 0. แสดงหน้าเว็บ Consent สำหรับให้ผู้ใช้ Login และกดยืนยัน (GET)
router.get('/authorize', async (req, res) => {
  try {
    const { client_id, redirect_uri, response_type, scope, state } = req.query;

    // ตรวจสอบพารามิเตอร์เบื้องต้น
    if (!client_id || !redirect_uri) {
      return res.status(400).send('Missing client_id or redirect_uri');
    }

    // ตรวจสอบว่าแอปมีอยู่จริง
    const app = await OAuthApp.findOne({ clientId: client_id });
    if (!app) {
      return res.status(400).send('Invalid Client ID');
    }

    // สร้าง HTML แบบฝัง (Stand-alone) สำหรับหน้า Consent
    const html = `
    <!DOCTYPE html>
    <html lang="th">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Authorize ${app.appName}</title>
      <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f4f7f6; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
        .container { background-color: white; padding: 30px; border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.08); width: 100%; max-width: 380px; text-align: center; }
        .app-logo { width: 80px; height: 80px; border-radius: 15px; object-fit: cover; margin-bottom: 15px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h2 { margin-top: 0; color: #333; font-size: 22px; }
        p { color: #666; margin-bottom: 25px; line-height: 1.5; font-size: 15px; }
        .btn { width: 100%; padding: 12px; margin-bottom: 10px; border: none; border-radius: 8px; font-size: 16px; cursor: pointer; transition: 0.2s; font-weight: bold; }
        .btn-allow { background-color: #1FAE4B; color: white; }
        .btn-allow:hover { background-color: #178c3b; }
        .btn-deny { background-color: #f44336; color: white; }
        .btn-deny:hover { background-color: #d32f2f; }
        .input-group { text-align: left; margin-bottom: 15px; }
        .input-group label { display: block; margin-bottom: 5px; color: #444; font-size: 14px; font-weight: bold; }
        .input-group input { width: 100%; padding: 10px; border: 1px solid #ccc; border-radius: 8px; box-sizing: border-box; font-size: 15px; }
        .input-group input:focus { outline: none; border-color: #1FAE4B; }
        #login-section, #consent-section { display: none; }
      </style>
    </head>
    <body>
      <div class="container">
        <img src="${app.appLogo || 'https://via.placeholder.com/80'}" alt="App Logo" class="app-logo" onerror="this.src='https://via.placeholder.com/80'">
        <h2>เชื่อมต่อด้วย ChatChat</h2>
        
        <div id="login-section">
          <p>กรุณาเข้าสู่ระบบเพื่ออนุญาตให้<br><b>${app.appName}</b> เข้าถึงข้อมูลของคุณ</p>
          <div class="input-group">
            <label>อีเมล</label>
            <input type="email" id="email" placeholder="you@example.com">
          </div>
          <div class="input-group">
            <label>รหัสผ่าน</label>
            <input type="password" id="password" placeholder="••••••••">
          </div>
          <button class="btn btn-allow" id="btnLogin">เข้าสู่ระบบ</button>
          <div id="login-error" style="color: #f44336; margin-top: 10px; display: none; font-size: 14px;">อีเมลหรือรหัสผ่านไม่ถูกต้อง</div>
        </div>

        <div id="consent-section">
          <p>แอปพลิเคชัน <b>${app.appName}</b><br>ต้องการขอสิทธิ์เข้าถึงข้อมูลโปรไฟล์พื้นฐานของคุณ</p>
          <button class="btn btn-allow" id="btnAllow">อนุญาตให้เข้าถึง (Allow)</button>
          <button class="btn btn-deny" id="btnDeny">ปฏิเสธ (Deny)</button>
        </div>
      </div>

      <!-- ซ่อนข้อมูลที่ต้องใช้ใน Data Attributes -->
      <div id="oauth-data" style="display: none;" data-client-id="${client_id}" data-redirect-uri="${redirect_uri}" data-state="${state || ''}" data-scope="${scope || ''}"></div>
      <!-- โหลด Script จากไฟล์ภายนอกเพื่อหลีกเลี่ยงข้อจำกัด CSP -->
      <script src="/public/js/oauth-consent.js"></script>
    </body>
    </html>`;

    res.send(html);
  } catch (error) {
    console.error('OAuth GET Authorize Error:', error);
    res.status(500).send('Internal Server Error');
  }
});

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