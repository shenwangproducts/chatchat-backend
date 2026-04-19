# Stripe Checkout Session & Payment Link Setup Guide

## 📋 Endpoint Documentation

### 1. Create Checkout Session (ตัวเลือกที่แนะนำ)
**Endpoint:** `POST /api/wallet/stripe/checkout-session`

**Request Body:**
```json
{
  "amount": 100,
  "coinAmount": 1000
}
```

**Response:**
```json
{
  "success": true,
  "message": "Checkout session created successfully",
  "url": "https://checkout.stripe.com/pay/cs_live_...",
  "sessionId": "cs_live_..."
}
```

**ลักษณะการทำงาน:**
- ผู้ใช้จะถูก redirect ไปยังหน้า Stripe Checkout (hosted page)
- รองรับการชำระเงินด้วยบัตรเครดิต (Card) และ PromptPay
- เหมาะสำหรับ Web app และ Mobile web
- สามารถตั้ง success/cancel URL ได้

---

### 2. Create Payment Link (ตัวเลือกอื่น)
**Endpoint:** `POST /api/wallet/stripe/payment-link`

**Request Body:**
```json
{
  "amount": 100,
  "coinAmount": 1000
}
```

**Response:**
```json
{
  "success": true,
  "message": "Payment link created successfully",
  "url": "https://buy.stripe.com/...",
  "linkId": "plink_..."
}
```

**ลักษณะการทำงาน:**
- สร้างลิงก์ที่สามารถแชร์ได้ (ไม่มีหมดอายุ)
- ใช้ได้กับทั้ง Web และ Mobile
- ไม่ต้องการ redirect - ส่งลิงก์ให้ผู้ใช้คลิก

---

## 🔧 Environment Variables ที่ต้องการ

เพิ่มใน `.env` ของคุณ:

```bash
# Stripe
STRIPE_SECRET_KEY=sk_live_xxxxx  # หรือ sk_test_xxxxx สำหรับ Test Mode
STRIPE_PUBLISHABLE_KEY=pk_live_xxxxx

# Frontend URL (สำหรับ success/cancel redirect)
FRONTEND_URL=https://yourapp.com
# หรือ
FRONTEND_URL=http://localhost:3000
```

---

## 📡 Webhook Setup (สำคัญ!)

### ขั้นตอน 1: สร้าง Webhook Endpoint

เพิ่มโค้ดนี้ในไฟล์ `server.js` (หลัง Stripe configuration):

```javascript
// =============================================
// 🔗 STRIPE WEBHOOK (Checkout Session)
// =============================================
app.post('/api/payment/webhook-checkout', express.raw({ type: 'application/json' }), async (req, res) => {
  const sig = req.headers['stripe-signature'];
  const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;

  let event;

  try {
    event = stripe.webhooks.constructEvent(req.body, sig, webhookSecret);
  } catch (err) {
    console.error('❌ Webhook signature verification failed:', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  // ✅ ตอบกลับ 200 ก่อน จากนั้นค่อยประมวลผลข้อมูล
  res.json({ received: true });

  // 🔄 ประมวลผลใน Background
  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    
    console.log('✅ Checkout session completed:', {
      sessionId: session.id,
      userId: session.metadata.userId,
      coinAmount: session.metadata.coinAmount,
      amountTotal: session.amount_total
    });

    try {
      const { userId, coinAmount } = session.metadata;
      const coinsToAdd = parseInt(coinAmount);

      // ✅ อัปเดตกระเป๋าเงินของผู้ใช้
      const wallet = await Wallet.findOne({ userId });
      if (wallet) {
        wallet.coinPoints += coinsToAdd;
        await wallet.save();

        // ✅ บันทึก Transaction
        const transaction = new Transaction({
          userId,
          walletId: wallet._id,
          type: 'topup',
          amount: session.amount_total / 100, // แปลงจากสตางค์เป็นบาท
          currency: 'THB',
          description: `Stripe Checkout: ${coinsToAdd} coins`,
          status: 'completed',
          referenceId: session.id,
          metadata: {
            sessionId: session.id,
            coinAmount: coinsToAdd,
            paymentMethod: session.payment_method_types?.[0] || 'card'
          }
        });
        await transaction.save();

        // ✅ สร้างการแจ้งเตือนสำหรับผู้ใช้
        await createCoinPointsNotification(userId, {
          points: coinsToAdd,
          description: 'Coins added via Stripe payment',
          balanceAfter: wallet.coinPoints,
          type: 'earn'
        });

        // ✅ ส่ง Push Notification (ถ้า Firebase enabled)
        await sendPushNotification(userId, {
          title: 'Payment Successful! ✅',
          body: `${coinsToAdd} coins added to your wallet`,
          data: { coins: coinsToAdd.toString() }
        });

        console.log('✅ User wallet updated successfully:', {
          userId,
          coinsAdded: coinsToAdd,
          newBalance: wallet.coinPoints
        });
      } else {
        console.error('❌ Wallet not found for user:', userId);
      }
    } catch (error) {
      console.error('❌ Error processing checkout session:', error);
    }
  }

  // 🚫 ใช้ในกรณีที่ payment ล้มเหลว
  if (event.type === 'checkout.session.expired') {
    const session = event.data.object;
    console.log('⏰ Checkout session expired:', session.id);
  }

  if (event.type === 'checkout.session.async_payment_failed') {
    const session = event.data.object;
    console.log('❌ Async payment failed:', session.id);
  }
});
```

---

### ขั้นตอน 2: ลงทะเบียน Webhook ใน Stripe Dashboard

1. เข้า [Stripe Dashboard](https://dashboard.stripe.com)
2. ไปที่ **Developers > Webhooks**
3. คลิก **Add endpoint**
4. ใส่ Endpoint URL:
   ```
   https://yourdomain.com/api/payment/webhook-checkout
   ```
5. เลือก Events ที่ต้องการรับ:
   - ✅ `checkout.session.completed`
   - ✅ `checkout.session.expired`
   - ✅ `checkout.session.async_payment_failed`
6. คลิก **Add endpoint**
7. คัดลอก **Signing secret** ไปใส่ใน `.env`:
   ```bash
   STRIPE_WEBHOOK_SECRET=whsec_xxxxx
   ```

---

## 📱 Frontend Implementation (Example)

### React Native / React:
```javascript
// สำหรับ Checkout Session
async function createCheckoutSession(amount, coinAmount) {
  const response = await fetch('/api/wallet/stripe/checkout-session', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${authToken}`
    },
    body: JSON.stringify({ amount, coinAmount })
  });

  const data = await response.json();
  if (data.success) {
    // Web: Open URL
    window.open(data.url, '_blank');
    
    // Mobile: Use Linking
    // Linking.openURL(data.url);
  }
}
```

---

## 🧪 Testing Guide

### Test ด้วย Stripe Test Mode:

1. ใน Stripe Dashboard ให้เปลี่ยนเป็น **Test Mode**
2. ใช้ **Test Card Numbers**:
   - Visa: `4242 4242 4242 4242`
   - Mastercard: `5555 5555 5555 4444`
   - PromptPay (Thailand): `3714 4993 2847 6816`

3. หมายเลขอื่น ๆ และวันหมดอายุ ใส่อะไรก็ได้ (ในอนาคต)
4. CVC: ใส่เลข 3 หลักอะไรก็ได้

### ทดสอบ Webhook ใน Local:

ใช้ **Stripe CLI** เพื่อ forward webhook ไปยัง localhost:

```bash
# 1. ดาวน์โหลด Stripe CLI จาก https://stripe.com/docs/stripe-cli
# 2. ล็อกอิน:
stripe login

# 3. Forward webhook:
stripe listen --forward-to localhost:30001/api/payment/webhook-checkout

# 4. ทดสอบ event:
stripe trigger checkout.session.completed
```

---

## ✅ Checklist

- [ ] เพิ่ม `STRIPE_SECRET_KEY` ใน `.env`
- [ ] เพิ่ม `STRIPE_WEBHOOK_SECRET` ใน `.env`
- [ ] เพิ่ม `FRONTEND_URL` ใน `.env`
- [ ] เพิ่ม Webhook endpoint code ในไฟล์ `server.js`
- [ ] ลงทะเบียน Webhook ใน Stripe Dashboard
- [ ] ทดสอบด้วย Test Mode
- [ ] ทดสอบ Webhook ด้วย Stripe CLI
- [ ] Restart server หลังเปลี่ยน `.env`

---

## 📌 ความแตกต่าง: Checkout Session vs Payment Link

| Feature | Checkout Session | Payment Link |
|---------|-----------------|--------------|
| Redirect ที่ Backend | ✅ ใช่ (ฝั่ง Backend) | ❌ ลิงก์ค้างไว้ |
| แชร์ได้ | ❌ ไม่ได้ | ✅ ใช่ |
| หมดอายุ | ✅ มีอายุ | ❌ ไม่หมดอายุ |
| Session-based | ✅ | ❌ |
| ใช้งานง่าย | ✅ | ✅ |

---

## 🐛 Troubleshooting

**ปัญหา: Webhook ไม่ทำงาน**
- ✅ ตรวจสอบ Webhook URL ถูกต้องไหม
- ✅ ตรวจสอบ `STRIPE_WEBHOOK_SECRET` ถูกต้องไหม
- ✅ ตรวจสอบ server กำลัง running หรือไม่

**ปัญหา: Amount error**
- ✅ ส่งเป็นเลขทศนิยมได้ (เช่น 100.50)
- ✅ ฝั่ง Stripe จะแปลงเป็นสตางค์เองแล้ว

**ปัญหา: Invalid signature**
- ✅ ตรวจสอบ `STRIPE_WEBHOOK_SECRET` ตรงกับ Dashboard ไหม

---

## 📞 Support

สำหรับปัญหาเพิ่มเติม ดู:
- [Stripe Checkout Docs](https://stripe.com/docs/payments/checkout)
- [Stripe Payment Links](https://stripe.com/docs/payment-links)
- [Stripe Webhooks](https://stripe.com/docs/webhooks)
