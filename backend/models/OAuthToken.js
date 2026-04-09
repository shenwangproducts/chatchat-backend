const mongoose = require('mongoose');

const oauthTokenSchema = new mongoose.Schema({
  authorizationCode: { type: String }, // รหัสชั่วคราวตอนผู้ใช้กดอนุญาต
  accessToken: { type: String }, // รหัสสำหรับดึงข้อมูล
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true }, // ไอดีผู้ใช้ที่กดอนุญาต
  clientId: { type: String, required: true }, // แอปที่ขออนุญาต
  scope: { type: String, default: 'profile email' },
  expiresAt: { type: Date, required: true } // เวลาหมดอายุ
});

module.exports = mongoose.model('OAuthToken', oauthTokenSchema);
