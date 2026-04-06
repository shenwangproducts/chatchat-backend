const mongoose = require('mongoose');

const chatSchema = new mongoose.Schema({
  participants: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  }],
  chatType: {
    type: String,
    enum: ['direct', 'group', 'official'],
    default: 'direct'
  },
  title: { type: String, required: true },
  description: { type: String },
  groupPicture: { type: String },
  settings: {
    allowVoiceCalls: { type: Boolean, default: true },
    allowVideoCalls: { type: Boolean, default: true },
    allowMemberPin: { type: Boolean, default: false },
    allowSendFiles: { type: Boolean, default: true },
    allowSendVideos: { type: Boolean, default: true },
    chatCooldown: { type: Number, default: 0 },
    groupPassword: { type: String, default: '' },
    announcementOnly: { type: Boolean, default: false }
  },
  admins: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  lastMessage: { type: String, default: '' },
  lastMessageTime: { type: Date, default: Date.now },
  unreadCount: { type: Map, of: Number, default: {} },
  isActive: { type: Boolean, default: true },
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

chatSchema.index({ participants: 1 });
chatSchema.index({ lastMessageTime: -1 });
chatSchema.index({ chatType: 1 });

module.exports = mongoose.model('Chat', chatSchema);