const mongoose = require('mongoose');

const rewardSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  type: {
    type: String,
    enum: ['earn', 'redeem', 'expire'],
    required: true
  },
  points: { type: Number, required: true },
  description: { type: String, required: true },
  balanceAfter: { type: Number, required: true },
  referenceId: { type: String },
  metadata: { type: Map, of: mongoose.Schema.Types.Mixed },
  createdAt: { type: Date, default: Date.now }
});

rewardSchema.index({ userId: 1, createdAt: -1 });

module.exports = mongoose.model('Reward', rewardSchema);