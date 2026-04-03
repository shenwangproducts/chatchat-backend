const mongoose = require('mongoose');

const appSettingsSchema = new mongoose.Schema({
  type: { type: String, default: 'default_settings' },
  language: { type: String, default: 'en' },
  theme: { type: String, default: 'white' },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('AppSettings', appSettingsSchema);