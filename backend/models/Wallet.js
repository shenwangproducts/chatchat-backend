const mongoose = require('mongoose');

const walletSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    unique: true
  },
  balance: { type: Number, default: 0.0 },
  coinPoints: { type: Number, default: 0 },
  currency: { type: String, default: 'THB' },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

walletSchema.index({ userId: 1 });

module.exports = mongoose.model('Wallet', walletSchema);