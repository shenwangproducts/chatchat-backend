const mongoose = require('mongoose');

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

module.exports = mongoose.model('MourningSettings', mourningSettingsSchema);