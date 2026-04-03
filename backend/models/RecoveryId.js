const mongoose = require('mongoose');

const recoveryIdSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  recoveryId: {
    type: String,
    required: true,
    unique: true
  },
  securityQuestion: { type: String, required: true },
  securityAnswer: { type: String, required: true },
  isActive: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

recoveryIdSchema.index({ userId: 1 });
recoveryIdSchema.index({ recoveryId: 1 });

module.exports = mongoose.model('RecoveryId', recoveryIdSchema);