const fs = require('fs');
const MediaUpload = require('../models/MediaUpload');

class VideoScannerService {
  /**
   * สแกนวิดีโอผ่าน Stream โดยไม่โหลดไฟล์ทั้งหมดลง RAM
   * @param {string} uploadId - รหัสของวิดีโออัปโหลด
   * @param {string} filePath - Path ของไฟล์วิดีโอในเครื่องเซิร์ฟเวอร์
   */
  static async scanContent(uploadId, filePath) {
    try {
      // 1. อัปเดตสถานะให้รู้ว่าระบบกำลังทำงาน
      await MediaUpload.findOneAndUpdate(
        { uploadId },
        { aiScanStatus: 'scanning' }
      );

      // 2. สร้าง Read Stream (ดึงไฟล์ขึ้น RAM ทีละนิด)
      // กำหนด highWaterMark เพื่อควบคุมขนาดของ Chunk เช่น 1024 * 1024 = 1MB ต่อรอบ
      const stream = fs.createReadStream(filePath, { highWaterMark: 1024 * 1024 });

      let isFlagged = false;
      let flaggedReason = '';

      // 3. ป้อนข้อมูล Stream ไปให้ AI API (เช่น Google Cloud Video / AWS)
      stream.on('data', (chunk) => {
        // ตัวอย่างเงื่อนไข: หากระบบ AI วิเคราะห์ Chunk ล่าสุดแล้วพบเนื้อหาอนาจารหรือการพนัน
        // if (AI_API.detects(chunk)) {
        //   isFlagged = true;
        //   flaggedReason = 'NSFW or Gambling Detected';
        //   stream.destroy(); // สั่งหยุดอ่าน Stream ทันที ประหยัด RAM ไม่ต้องสแกนส่วนที่เหลือ
        // }
      });

      // 4. เมื่ออ่านวิดีโอจนจบ (หรือถูกสั่งหยุดด้วยคำสั่ง destroy)
      stream.on('close', async () => {
        if (isFlagged) {
          await MediaUpload.findOneAndUpdate(
            { uploadId },
            { 
              aiScanStatus: 'flagged',
              isSuspended: true, // ระงับการมองเห็นทันที
              suspensionReason: flaggedReason,
              visibility: 'private' 
            }
          );
        } else {
          await MediaUpload.findOneAndUpdate(
            { uploadId },
            { aiScanStatus: 'clean' }
          );
        }

        // 5. ล้างไฟล์ขยะและคืนหน่วยความจำทันที (Garbage collection / ลบไฟล์ Temp)
        // หากมีไฟล์แปลงเสียงหรือรูปย่อที่สร้างจากวิดีโอ ให้สั่งลบทิ้งตรงนี้
        // if (fs.existsSync(tempFiles)) fs.unlinkSync(tempFiles);
      });

      stream.on('error', (err) => {
        console.error(`[VideoScanner] Error scanning file ${uploadId}:`, err);
      });

    } catch (error) {
      console.error(`[VideoScanner] Failed for ${uploadId}:`, error);
    }
  }
}

module.exports = VideoScannerService;