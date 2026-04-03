const mongoose = require('mongoose');

const storySchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true
  },
  type: {
    type: String,
    enum: ['text', 'image', 'video'],
    default: 'text'
  },
  mediaUrl: String,
  thumbnailUrl: String,
  backgroundColor: { type: String, default: '#000000' },
  textItems: [mongoose.Schema.Types.Mixed],
  stickers: [mongoose.Schema.Types.Mixed],
  visibility: {
    type: String,
    enum: ['public', 'friends', 'private', 'specific'],
    default: 'public'
  },
  specificViewers: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  allowComments: { type: Boolean, default: true },
  viewers: [{
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    viewedAt: { type: Date, default: Date.now }
  }],
  createdAt: { type: Date, default: Date.now },
  expiresAt: { type: Date, required: true, index: true }
});

// Auto-delete stories after expiration (TTL)
storySchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });
storySchema.index({ userId: 1, createdAt: -1 });

module.exports = mongoose.model('Story', storySchema);