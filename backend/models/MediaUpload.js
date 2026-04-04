const mongoose = require('mongoose');

const mediaUploadSchema = new mongoose.Schema({
  uploadId: { type: String, unique: true, required: true, index: true }, // Unique identifier for tracking
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true
  },
  publicId: { type: String }, // ✅ Cloudinary public_id
  fileName: { type: String, required: true },
  fileType: { type: String, required: true }, // 'video', 'photo', 'camera'
  mimeType: { type: String, required: true },
  fileSize: { type: Number, required: true }, // in bytes
  title: { type: String, required: true },
  description: { type: String },
  filePath: { type: String, required: true }, // saved location
  fileUrl: { type: String }, // URL to access the file
  thumbnailUrl: { type: String }, // For videos
  duration: { type: Number }, // Video duration in seconds
  uploadProgress: { type: Number, default: 0 }, // 0-100%
  status: {
    type: String,
    enum: ['pending', 'uploading', 'completed', 'failed', 'cancelled'],
    default: 'pending',
    index: true
  },
  // ✅ ส่วนที่เพิ่มใหม่สำหรับ Post Settings
  visibility: {
    type: String,
    enum: ['public', 'friends', 'private'],
    default: 'public'
  },
  commentPermission: {
    type: String,
    enum: ['public', 'friends_followers', 'private'],
    default: 'public'
  },
  shareToStory: { type: Boolean, default: false },
  shareToGroups: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Chat' }],
  scheduledTime: { type: Date, sparse: true },
  collaborators: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  // ------------------------------------

  // ✅ ส่วนที่เพิ่มใหม่สำหรับ Video Content AI Scanner
  aiScanStatus: {
    type: String,
    enum: ['pending', 'scanning', 'clean', 'flagged'],
    default: 'pending',
    index: true
  },
  isSuspended: { type: Boolean, default: false },
  suspensionReason: { type: String },

  // ✅ ส่วนที่เพิ่มใหม่สำหรับ Fake Engagement Tracking
  hasSuspiciousEngagement: { type: Boolean, default: false, index: true },
  suspiciousLikesCount: { type: Number, default: 0 },
  suspiciousViewsCount: { type: Number, default: 0 },

  uploadedAt: { type: Date, default: Date.now },
  completedAt: { type: Date, sparse: true },
  cancelledAt: { type: Date, sparse: true },
  errorMessage: { type: String },
  retryCount: { type: Number, default: 0 },
  metadata: { type: Map, of: mongoose.Schema.Types.Mixed },
  likesCount: { type: Number, default: 0 },
  sharesCount: { type: Number, default: 0 }
});

mediaUploadSchema.index({ userId: 1, uploadedAt: -1 });
mediaUploadSchema.index({ status: 1, uploadedAt: -1 });
mediaUploadSchema.index({ uploadId: 1 });

module.exports = mongoose.model('MediaUpload', mediaUploadSchema);