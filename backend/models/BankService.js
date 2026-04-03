const mongoose = require('mongoose');

const bankServiceSchema = new mongoose.Schema({
  code: { type: String, required: true, unique: true },
  name: { type: String, required: true },
  nameEn: { type: String, required: true },
  nameZh: { type: String, required: true },
  color: { type: String, default: '#000000' },
  icon: { type: String, default: 'account_balance' },
  deeplink: {
    scan_pay: String,
    transfer: String,
    topup: String,
    withdraw: String
  },
  packageName: String,
  isActive: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

bankServiceSchema.index({ code: 1 });
bankServiceSchema.index({ isActive: 1 });

module.exports = mongoose.model('BankService', bankServiceSchema);