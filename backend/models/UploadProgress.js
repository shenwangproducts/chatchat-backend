const mongoose = require('mongoose');

const uploadProgressSchema = new mongoose.Schema({
  uploadId: { type: String, unique: true, required: true, index: true },
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true
  },
  bytesUploaded: { type: Number, default: 0 },
  totalBytes: { type: Number, required: true },
  percentComplete: { type: Number, default: 0 }, // 0-100
  status: {
    type: String,
    enum: ['pending', 'uploading', 'paused', 'completed', 'failed', 'cancelled'],
    default: 'pending'
  },
  speed: { type: Number, default: 0 }, // bytes per second
  remainingTime: { type: Number, default: 0 }, // seconds
  startTime: { type: Date, default: Date.now },
  lastUpdateTime: { type: Date, default: Date.now },
  completedTime: { type: Date, sparse: true },
  errorMessage: { type: String },
  chunks: [{
    chunkIndex: { type: Number, required: true },
    size: { type: Number, required: true },
    status: {
      type: String,
      enum: ['pending', 'uploading', 'completed', 'failed'],
      default: 'pending'
    },
    uploadedAt: { type: Date }
  }]
});

uploadProgressSchema.index({ uploadId: 1 });
uploadProgressSchema.index({ userId: 1, uploadId: 1 });

module.exports = mongoose.model('UploadProgress', uploadProgressSchema);