const mongoose = require('mongoose');

const notificationSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true
  },
  type: {
    type: String,
    enum: [
      'wallet_transaction',    // ธุรกรรมกระเป๋าเงิน
      'wallet_points',         // คะแนนคอยน์
      'chat_message',          // ข้อความใหม่
      'chat_call',             // การโทรเข้า
      'friend_request',        // คำขอเป็นเพื่อน
      'friend_accept',         // ยอมรับเพื่อน
      'profile_visit',         // มีคนเยี่ยมชมโปรไฟล์
      'profile_update',        // อัปเดตโปรไฟล์
      'bank_service',          // ใช้บริการธนาคาร
      'identity_verify',       // ยืนยันตัวตนสำเร็จ
      'system_alert',          // แจ้งเตือนระบบ
      'reward_earned'          // ได้รับรางวัล
    ],
    required: true,
    index: true
  },
  title: {
    type: String,
    required: true
  },
  message: {
    type: String,
    required: true
  },
  icon: {
    type: String,
    default: '🔔'
  },
  color: {
    type: String,
    default: '#1FAE4B'
  },
  data: {
    type: Map,
    of: mongoose.Schema.Types.Mixed,
    default: {}
  },
  isRead: {
    type: Boolean,
    default: false,
    index: true
  },
  isArchived: {
    type: Boolean,
    default: false
  },
  priority: {
    type: String,
    enum: ['low', 'medium', 'high', 'urgent'],
    default: 'medium'
  },
  expiresAt: {
    type: Date,
    index: true,
    expires: 30 * 24 * 60 * 60 // 30 วัน
  },
  createdAt: {
    type: Date,
    default: Date.now,
    index: true
  },
  readAt: {
    type: Date 
  },
  sourceId: { 
    type: String 
  }
});

// ✅ Indexes สำหรับประสิทธิภาพ
notificationSchema.index({ userId: 1, isRead: 1, createdAt: -1 });
notificationSchema.index({ userId: 1, type: 1, createdAt: -1 });
notificationSchema.index({ sourceId: 1 });
notificationSchema.index({ userId: 1, isArchived: 1 });

module.exports = mongoose.model('Notification', notificationSchema);