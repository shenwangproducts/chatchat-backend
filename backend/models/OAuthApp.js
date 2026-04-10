const mongoose = require('mongoose');

const oauthAppSchema = new mongoose.Schema({
  appName: { type: String, required: true }, // ชื่อแอป เช่น "Shopee", "Wongnai"
  appLogo: { type: String }, // URL โลโก้แอป
  clientId: { type: String, required: true, unique: true }, // รหัส Client ID
  clientSecret: { type: String, required: true }, // รหัสลับ
  redirectUris: [{ type: String, required: true }], // URL ที่อนุญาตให้เด้งกลับไป
  developerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }, // เจ้าของแอป
  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('OAuthApp', oauthAppSchema);