// =============================================
// 🔗 STRIPE WEBHOOK (Checkout Session)
// =============================================
// 📍 ที่ตั้ง: เพิ่มโค้ดนี้ลงในไฟล์ server.js หลัง app.post('/api/payment/webhook', ...)

app.post('/api/payment/webhook-checkout', express.raw({ type: 'application/json' }), async (req, res) => {
  const sig = req.headers['stripe-signature'];
  const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;

  // ⚠️ ตรวจสอบว่า STRIPE_WEBHOOK_SECRET ถูกตั้งหรือไม่
  if (!webhookSecret) {
    console.warn('⚠️ STRIPE_WEBHOOK_SECRET not set in .env');
    return res.status(400).send('Webhook secret not configured');
  }

  let event;

  try {
    // ✅ ยืนยันลายเซ็นของ webhook จาก Stripe
    event = stripe.webhooks.constructEvent(req.body, sig, webhookSecret);
    console.log('✅ Webhook signature verified:', event.type);
  } catch (err) {
    console.error('❌ Webhook signature verification failed:', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  // ✅ ตอบกลับ 200 ทันที เพื่อบอก Stripe ว่า webhook ได้รับเรียบร้อย
  // ❗ สำคัญ: ต้องตอบกลับอย่างรวดเร็วเพื่อไม่ให้ Stripe retry
  res.json({ received: true });

  // 🔄 ประมวลผลข้อมูลใน Background (ไม่บล็อก response)
  handleCheckoutEvent(event).catch(error => {
    console.error('❌ Error handling checkout event:', error);
    // สามารถบันทึกข้อผิดพลาดลง database หรือ logging service ได้
  });
});

// 🔧 ฟังก์ชันสำหรับประมวลผล Checkout Event
const handleCheckoutEvent = async (event) => {
  switch (event.type) {
    case 'checkout.session.completed':
      return await handleCheckoutCompleted(event.data.object);
    
    case 'checkout.session.expired':
      return await handleCheckoutExpired(event.data.object);
    
    case 'checkout.session.async_payment_failed':
      return await handleAsyncPaymentFailed(event.data.object);
    
    default:
      console.log('ℹ️ Unhandled event type:', event.type);
  }
};

// ✅ จัดการกรณีชำระเงินสำเร็จ
const handleCheckoutCompleted = async (session) => {
  console.log('✅ Processing checkout.session.completed:', {
    sessionId: session.id,
    userId: session.metadata?.userId,
    coinAmount: session.metadata?.coinAmount,
    amountTotal: session.amount_total,
    paymentStatus: session.payment_status
  });

  try {
    const { userId, coinAmount } = session.metadata;

    // ✅ Validate metadata
    if (!userId || !coinAmount) {
      console.error('❌ Missing metadata in session:', session.metadata);
      return;
    }

    const coinsToAdd = parseInt(coinAmount);
    if (isNaN(coinsToAdd) || coinsToAdd <= 0) {
      console.error('❌ Invalid coinAmount:', coinAmount);
      return;
    }

    // ✅ ดึงข้อมูล Wallet
    const wallet = await Wallet.findOne({ userId });
    if (!wallet) {
      console.error('❌ Wallet not found for user:', userId);
      return;
    }

    // ✅ อัปเดตยอดเหรียญ
    const oldBalance = wallet.coinPoints;
    wallet.coinPoints += coinsToAdd;
    await wallet.save();

    console.log('💰 Wallet updated:', {
      userId,
      oldBalance,
      coinsAdded: coinsToAdd,
      newBalance: wallet.coinPoints
    });

    // ✅ บันทึก Transaction history
    const transaction = new Transaction({
      userId,
      walletId: wallet._id,
      type: 'topup',
      amount: session.amount_total / 100, // แปลงจากสตางค์เป็นบาท (เช่น 10000 = 100 บาท)
      currency: 'THB',
      description: `Stripe Checkout Payment: ${coinsToAdd} coins`,
      status: 'completed',
      referenceId: session.id, // ใช้ Stripe session ID เป็น reference
      metadata: {
        sessionId: session.id,
        coinAmount: coinsToAdd,
        paymentMethod: session.payment_method_types?.[0] || 'unknown',
        customerEmail: session.customer_email,
        paymentIntentId: session.payment_intent
      }
    });
    await transaction.save();

    console.log('📝 Transaction recorded:', {
      transactionId: transaction._id,
      sessionId: session.id
    });

    // ✅ ส่ง In-app Notification
    try {
      await createCoinPointsNotification(userId, {
        points: coinsToAdd,
        description: 'Payment received successfully via Stripe Checkout',
        balanceAfter: wallet.coinPoints,
        type: 'earn'
      });
      console.log('📢 In-app notification sent to user:', userId);
    } catch (notifError) {
      console.error('⚠️ Failed to send notification:', notifError.message);
    }

    // ✅ ส่ง Push Notification (ถ้า Firebase enabled)
    try {
      await sendPushNotification(userId, {
        title: '✅ Payment Successful!',
        body: `${coinsToAdd} coins added to your wallet`,
        data: {
          coins: coinsToAdd.toString(),
          newBalance: wallet.coinPoints.toString()
        }
      });
      console.log('🔔 Push notification sent to user:', userId);
    } catch (pushError) {
      console.error('⚠️ Failed to send push notification:', pushError.message);
    }

    // ✅ ส่ง Email confirmation (ถ้า SendGrid enabled)
    try {
      if (process.env.SENDGRID_API_KEY && session.customer_email) {
        const emailHtml = `
          <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; text-align: center; border-radius: 10px 10px 0 0;">
              <h1 style="color: white; margin: 0;">✅ Payment Received</h1>
            </div>
            <div style="background: #f8f9fa; padding: 30px; border-radius: 0 0 10px 10px;">
              <p style="color: #333; font-size: 16px;">Thank you for your purchase!</p>
              <table style="width: 100%; margin: 20px 0;">
                <tr><td style="padding: 8px;">Coins Added:</td><td style="text-align: right; font-weight: bold;">${coinsToAdd}</td></tr>
                <tr><td style="padding: 8px;">Amount Paid:</td><td style="text-align: right;">${session.amount_total / 100} THB</td></tr>
                <tr><td style="padding: 8px;">Transaction ID:</td><td style="text-align: right; font-size: 12px;">${session.id}</td></tr>
              </table>
            </div>
          </div>
        `;

        const msg = {
          to: session.customer_email,
          from: process.env.SENDGRID_FROM_EMAIL || 'noreply@chatchat.app',
          subject: '✅ Payment Receipt - Coins Added',
          html: emailHtml
        };

        await sgMail.send(msg);
        console.log('📧 Confirmation email sent to:', session.customer_email);
      }
    } catch (emailError) {
      console.error('⚠️ Failed to send email:', emailError.message);
    }

  } catch (error) {
    console.error('❌ Error processing checkout completed:', error);
    // บันทึกข้อผิดพลาดเพื่อ manual investigation
    console.error('Session data:', session);
  }
};

// ⏰ จัดการกรณี Session หมดอายุ
const handleCheckoutExpired = async (session) => {
  console.log('⏰ Checkout session expired:', {
    sessionId: session.id,
    userId: session.metadata?.userId,
    expiresAt: new Date(session.expires_at * 1000)
  });

  try {
    const { userId } = session.metadata;
    if (!userId) return;

    // สามารถส่ง notification ให้ผู้ใช้ว่า session หมดอายุแล้ว
    await createNotification({
      userId,
      type: 'payment_expired',
      title: '⏰ Payment Session Expired',
      message: 'Your checkout session has expired. Please try again.',
      icon: '⏰',
      color: '#FF9800',
      priority: 'medium'
    });

    console.log('📢 Expiry notification sent to user:', userId);
  } catch (error) {
    console.error('⚠️ Error handling checkout expiry:', error.message);
  }
};

// ❌ จัดการกรณี Async payment ล้มเหลว
const handleAsyncPaymentFailed = async (session) => {
  console.log('❌ Async payment failed:', {
    sessionId: session.id,
    userId: session.metadata?.userId,
    paymentIntent: session.payment_intent
  });

  try {
    const { userId } = session.metadata;
    if (!userId) return;

    // บันทึก failed transaction
    const transaction = new Transaction({
      userId,
      type: 'topup',
      amount: session.amount_total / 100,
      currency: 'THB',
      description: 'Stripe Checkout Payment Failed',
      status: 'failed',
      referenceId: session.id,
      metadata: {
        sessionId: session.id,
        reason: 'async_payment_failed'
      }
    });
    await transaction.save();

    // ส่ง notification
    await createNotification({
      userId,
      type: 'payment_failed',
      title: '❌ Payment Failed',
      message: 'Your payment could not be processed. Please try again.',
      icon: '❌',
      color: '#F44336',
      priority: 'high'
    });

    console.log('📢 Payment failed notification sent to user:', userId);
  } catch (error) {
    console.error('⚠️ Error handling payment failure:', error.message);
  }
};

// =============================================
// 📋 EVENT TYPE REFERENCE
// =============================================
/*
Stripe Checkout Session Events:
- checkout.session.completed    → ✅ การชำระเงินสำเร็จ
- checkout.session.expired      → ⏰ Session หมดอายุ (มักจะเกิดขึ้นก่อน 24 ชั่วโมง)
- checkout.session.async_payment_failed → ❌ Async payment ล้มเหลว (เช่น PromptPay)

🔗 Full Event List: https://stripe.com/docs/api/events/types
*/
