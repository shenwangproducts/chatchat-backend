# ⚡ Stripe Checkout/Payment Link Implementation - Quick Start

## ✅ สิ่งที่เพิ่มเข้าไปแล้ว

### 1️⃣ **Endpoints ใหม่ 2 แบบ** (ใน server.js)

#### A) Checkout Session (แนะนำ)
```
POST /api/wallet/stripe/checkout-session
Body: { amount: 100, coinAmount: 1000 }
Response: { success, url, sessionId }
```
- Redirect ไปหน้า Stripe Checkout
- รองรับ Card + PromptPay
- เหมาะสำหรับ Web & Mobile

#### B) Payment Link
```
POST /api/wallet/stripe/payment-link
Body: { amount: 100, coinAmount: 1000 }
Response: { success, url, linkId }
```
- ส่งลิงก์แบบยาว
- ไม่หมดอายุ
- สามารถแชร์ได้

---

## 🔧 ขั้นตอนการติดตั้ง

### 1. ตั้งค่า Environment Variables
ใน `.env` เพิ่ม:
```bash
STRIPE_SECRET_KEY=sk_test_xxxxx         # ค้นหาจาก Stripe Dashboard
STRIPE_WEBHOOK_SECRET=whsec_xxxxx       # เก็บไว้ชั่วคราว (หลังจากสร้าง Webhook)
FRONTEND_URL=http://localhost:3000      # URL ของ Frontend
```

### 2. เพิ่ม Webhook Handler
คัดลอกโค้ดจาก `STRIPE_WEBHOOK_EXAMPLE.js` และวางลงใน `server.js`

**วางไว้ที่:**
- หลัง `app.post('/api/payment/webhook', ...)` (webhook ปัจจุบัน)
- ก่อน Router imports (บรรทัดที่ 1270 ประมาณ)

### 3. ลงทะเบียน Webhook ใน Stripe Dashboard

1. ไปที่ [Stripe Dashboard](https://dashboard.stripe.com)
2. **Developers → Webhooks → Add Endpoint**
3. ใส่ URL:
   ```
   https://yourdomain.com/api/payment/webhook-checkout
   ```
   (สำหรับ Local ใช้ Stripe CLI: `stripe listen --forward-to localhost:30001/api/payment/webhook-checkout`)
4. เลือก Events:
   - `checkout.session.completed`
   - `checkout.session.expired`
   - `checkout.session.async_payment_failed`
5. Copy Signing Secret ไปใส่ใน `.env` เป็น `STRIPE_WEBHOOK_SECRET`

### 4. Restart Server
```bash
npm start
```

---

## 🧪 ทดสอบ

### ใช้ Test Mode
1. Stripe Dashboard เป็น **Test Mode**
2. ใช้ Test Card: `4242 4242 4242 4242`
3. Expiry: `12/26` (อนาคต)
4. CVC: `123` (อะไรก็ได้)

### ทดสอบ Local Webhook
```bash
# Terminal 1: Run server
npm start

# Terminal 2: Listen to webhooks
stripe login
stripe listen --forward-to localhost:30001/api/payment/webhook-checkout

# Terminal 3: Trigger test event
stripe trigger checkout.session.completed
```

---

## 📁 ไฟล์ที่สร้างขึ้น

| ไฟล์ | ลักษณะการใช้ |
|------|-----------|
| `STRIPE_CHECKOUT_SETUP.md` | 📖 Documentation ฉบับเต็ม |
| `STRIPE_WEBHOOK_EXAMPLE.js` | 📋 Code template สำหรับ Webhook |
| `.env.stripe.example` | 🔧 Environment variables |
| `STRIPE_QUICK_START.md` | ⚡ Quick start (ไฟล์นี้) |

---

## 🎯 Frontend Usage Example

### React/React Native:
```javascript
// 1. สร้าง Checkout Session
const response = await fetch('/api/wallet/stripe/checkout-session', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${token}`
  },
  body: JSON.stringify({ amount: 100, coinAmount: 1000 })
});

const data = await response.json();
// 2. Redirect ไป Stripe
if (data.success) {
  window.location.href = data.url; // Web
  // หรือ
  // Linking.openURL(data.url);  // Mobile
}
```

---

## ❌ หากสิ่งใดไม่ทำงาน

| ปัญหา | สาเหตุ | วิธีแก้ |
|------|-------|--------|
| Webhook ไม่ทำงาน | Secret ผิด | ตรวจสอบ STRIPE_WEBHOOK_SECRET ตรงกับ Dashboard |
| Error 401 | Token หมดอายุ | ใช้ Authorization header ให้ถูก |
| Status 500 | Missing env var | เพิ่มตัวแปรทั้งหมดในไฟล์ `.env` |
| Balance ไม่เพิ่ม | Webhook ไม่ถูกทริกเกอร์ | ตรวจสอบว่า `/api/payment/webhook-checkout` ถูก register |

---

## 📚 อ่านเพิ่มเติม

- [Stripe Checkout Docs](https://stripe.com/docs/payments/checkout)
- [Stripe Webhooks](https://stripe.com/docs/webhooks)
- [Stripe Test Cards](https://stripe.com/docs/testing)
- [Stripe Thailand Setup](https://stripe.com/docs/thailand)

---

## ✅ Checklist

- [ ] เพิ่ม `STRIPE_SECRET_KEY` ใน `.env`
- [ ] เพิ่ม Webhook handler code ลง `server.js`
- [ ] ลงทะเบียน Webhook URL ใน Stripe Dashboard
- [ ] เพิ่ม `STRIPE_WEBHOOK_SECRET` ใน `.env`
- [ ] Restart server
- [ ] ทดสอบ POST ไปยัง `/api/wallet/stripe/checkout-session`
- [ ] ตรวจสอบว่า coins เพิ่มหลังชำระเงิน

---

## 💡 Tips

- 🟢 **Recommended**: ใช้ Checkout Session (มีความปลอดภัยสูงกว่า)
- 📱 **Mobile**: ทั้งสองแบบใช้ได้เหมือนกัน
- 🔒 ไม่ต้องเก็บ Card details (Stripe ดูแลให้)
- 🎯 ใช้ `metadata` เพื่อดึง user info หลังการชำระ

---

**หากมีปัญหา ให้ตรวจสอบ logs ใน server และ Stripe Dashboard**
