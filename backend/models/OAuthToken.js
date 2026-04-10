const mongoose = require('mongoose');

const oauthTokenSchema = new mongoose.Schema({
  authorizationCode: { type: String }, // รหัสชั่วคราวตอนผู้ใช้กดอนุญาต
  accessToken: { type: String }, // รหัสสำหรับดึงข้อมูล
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true }, // ไอดีผู้ใช้ที่กดอนุญาต
  clientId: { type: String, required: true }, // แอปที่ขออนุญาต
  redirectUri: { type: String }, // เก็บ URL ส่งกลับ (ป้องกันการสวมรอย)
  scope: { type: String, default: 'profile email' },
  expiresAt: { type: Date, required: true, index: { expires: 0 } } // ให้ระบบลบ token อัตโนมัติเมื่อหมดอายุ
});

module.exports = mongoose.model('OAuthToken', oauthTokenSchema);
