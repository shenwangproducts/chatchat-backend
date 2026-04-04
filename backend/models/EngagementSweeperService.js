const cron = require('node-cron');
const MediaUpload = require('../models/MediaUpload');

class EngagementSweeperService {
  /**
   * สร้าง Background Job สำหรับรันทุกตี 3 เพื่อล้างยอดปั๊มปลอม
   */
  static initSweeperJob() {
    // รันตอน 03:00 น. ของทุกวัน (ช่วงที่ทราฟฟิกแอปเบาบางที่สุด)
    cron.schedule('0 3 * * *', async () => {
      console.log('🧹 [Engagement Sweeper] Starting background sweep job...');
      const startTime = Date.now();

      try {
        // 1. ดึงเฉพาะโพสต์ที่ถูกระบบจับตาไว้ว่ามียอดพุ่งผิดปกติ
        const suspiciousPosts = await MediaUpload.find({ hasSuspiciousEngagement: true });

        if (suspiciousPosts.length === 0) {
          console.log('✅ [Engagement Sweeper] No suspicious engagements found today.');
          return;
        }

        // 2. เตรียมชุดคำสั่งล้างข้อมูลแบบระบุตัวตนและจัดรูปการอัปเดต (Bulk Operations)
        const bulkOperations = suspiciousPosts.map((post) => {
          // หักลบยอดปลอมออก เพื่อรักษาความเป็นจริง (ใช้ Math.max ป้องกันยอดติดลบ)
          const validLikes = Math.max(0, post.likesCount - post.suspiciousLikesCount);
          
          return {
            updateOne: {
              filter: { _id: post._id },
              update: {
                $set: {
                  likesCount: validLikes,
                  hasSuspiciousEngagement: false, // รีเซ็ตสถานะเพื่อหยุดการเฝ้าระวัง
                  suspiciousLikesCount: 0,
                  suspiciousViewsCount: 0
                }
              }
            }
          };
        });

        // 3. รันคำสั่ง Batch Update ทีละกลุ่ม (Chunk Processing)
        // เพื่อไม่ให้ Server กิน RAM มากเกินไป หรือเกิดการ Block การใช้งาน Database ของ User อื่น
        const BATCH_SIZE = 500; // ทำทีละ 500 โพสต์
        for (let i = 0; i < bulkOperations.length; i += BATCH_SIZE) {
          const batch = bulkOperations.slice(i, i + BATCH_SIZE);
          await MediaUpload.collection.bulkWrite(batch);
        }

        const duration = (Date.now() - startTime) / 1000;
        console.log(`✅ [Engagement Sweeper] Processed ${suspiciousPosts.length} posts in ${duration}s.`);
      } catch (error) {
        console.error('❌ [Engagement Sweeper] Job failed:', error);
      }
    });
  }
}

module.exports = EngagementSweeperService;