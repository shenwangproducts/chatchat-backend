const mongoose = require('mongoose');

const identityVerificationSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true
  },
  verificationMethod: {
    type: String,
    enum: ['id_card', 'passport'],
    required: true
  },
  status: {
    type: String,
    enum: ['pending', 'verified', 'rejected', 'expired'],
    default: 'pending',
    index: true
  },
  documentNumber: {
    type: String,
    required: true,
    trim: true
  },
  fullName: {
    type: String,
    required: true,
    trim: true
  },
  birthDate: {
    type: Date
  },
  nationality: {
    type: String,
    trim: true
  },
  expiryDate: {
    type: Date
  },
  faceScanData: {
    stepsCompleted: { type: Number, default: 0 },
    totalSteps: { type: Number, default: 6 },
    scanResults: [{
      step: { type: Number, required: true },
      title: { type: String, required: true },
      status: {
        type: String, 
        enum: ['pending', 'completed', 'failed'],
        default: 'pending'
      },
      timestamp: { type: Date, default: Date.now }
    }],
    completedAt: Date
  },
  verifiedAt: { type: Date },
  rejectedAt: { type: Date },
  rejectionReason: { type: String },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

identityVerificationSchema.index({ userId: 1, status: 1 });

module.exports = mongoose.model('IdentityVerification', identityVerificationSchema);