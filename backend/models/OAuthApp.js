const mongoose = require('mongoose');

const oauthAppSchema = new mongoose.Schema({
  name: { type: String, required: true }, // ชื่อแอป เช่น "Shopee", "Wongnai"
  clientId: { type: String, required: true, unique: true }, // รหัส Client ID
  clientSecret: { type: String, required: true }, // รหัสลับ
  redirectUris: [{ type: String, required: true }], // URL ที่อนุญาตให้เด้งกลับไป
  creatorId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }, // เจ้าของแอป
  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('OAuthApp', oauthAppSchema);