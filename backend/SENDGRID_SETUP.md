# SendGrid Email Service Setup Guide

## 🚀 Quick Start

Your backend is now configured to send emails via SendGrid. Follow these steps to enable it:

### Step 1: Get Your SendGrid API Key

1. Go to [SendGrid Dashboard](https://app.sendgrid.com)
2. Navigate to **Settings** → **API Keys**
3. Click **Create API Key**
4. Name it (e.g., "ChatChat-Backend")
5. Copy the API key (you'll only see it once!)

### Step 2: Add Environment Variables

Add these to your `.env` file:

```env
# SendGrid Configuration
SENDGRID_API_KEY=SG.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
SENDGRID_FROM_EMAIL=noreply@chatchat.app
```

**Important:** Replace the email with your actual SendGrid verified sender email. If you don't have one verified yet:

1. In SendGrid Dashboard, go to **Settings** → **Sender Authentication**
2. Click **Create New Sender**
3. Fill in your business details
4. Verify the sender email (click link in verification email)

### Step 3: Verify Setup

```bash
# Test the connection
node server.js

# You should see:
# ✅ Firebase initialized successfully
# ✅ SendGrid initialized successfully
```

---

## 📧 Features Enabled

Once configured, the following email features are active:

### 1. Email Verification (New User Registration)
- **Endpoint:** `POST /api/user/send-verification-email`
- **Purpose:** Sends verification email with a 24-hour link
- **Email Features:**
  - Professional HTML template
  - One-click verification button
  - Backup verification link
  - 24-hour expiration notice

### 2. Account Recovery
- **Endpoint:** `POST /api/recovery/create`
- **Purpose:** Sends recovery ID and security question
- **Email Features:**
  - Recovery ID displayed clearly
  - Security question reminder
  - Professional formatting
  - Security warning

---

## 🔧 Environment Variables Reference

| Variable | Required | Example | Description |
|----------|----------|---------|-------------|
| `SENDGRID_API_KEY` | ✅ Yes | `SG.xxxxx...` | Your SendGrid API key |
| `SENDGRID_FROM_EMAIL` | ✅ Yes | `noreply@chatchat.app` | Your verified sender email |
| `NODE_ENV` | ❌ No | `production` | Set to `production` to hide tokens in responses |

---

## 📝 Sample .env Configuration

```env
# Application
PORT=30001
NODE_ENV=production

# MongoDB
MONGODB_URI=mongodb+srv://user:password@cluster.mongodb.net/chatchat

# JWT
JWT_SECRET=your-secret-key-change-this

# Cloudinary
CLOUDINARY_CLOUD_NAME=your-cloud-name
CLOUDINARY_API_KEY=your-api-key
CLOUDINARY_API_SECRET=your-api-secret

# SendGrid Email Service
SENDGRID_API_KEY=SG.xxxxxxxxxxxxxxxxxx_xxxxxx
SENDGRID_FROM_EMAIL=noreply@chatchat.app

# Firebase
FIREBASE_SERVICE_ACCOUNT_KEY={"type":"service_account",...}

# Admin API
ADMIN_API_KEY=your-admin-key
```

---

## 🧪 Testing Email Endpoints

### Test Email Verification
```bash
curl -X POST http://localhost:30001/api/user/send-verification-email \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json"
```

Response:
```json
{
  "success": true,
  "message": "Verification email sent successfully",
  "email": "user@example.com",
  "verificationToken": "token_here"  // Only in development mode
}
```

### Test Recovery Email
```bash
curl -X POST http://localhost:30001/api/recovery/create \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "securityQuestion": "What was your first pet's name?",
    "securityAnswer": "Fluffy"
  }'
```

---

## ⚠️ Common Issues & Solutions

### Issue: "Email service is not configured"
**Solution:** 
- Verify `SENDGRID_API_KEY` is set in `.env`
- Restart the server after adding the variable
- Check that the API key is valid (not expired or revoked)

### Issue: "Email sent but not received"
**Solution:**
- Verify the `SENDGRID_FROM_EMAIL` is a verified sender in SendGrid
- Check spam/junk folder
- Verify recipient email is correct
- Check SendGrid Activity feed for bounce/dropped notifications

### Issue: "401 Unauthorized from SendGrid"
**Solution:**
- Ensure `SENDGRID_API_KEY` is copied correctly (no spaces)
- API key might be revoked - create a new one
- Key might be for wrong SendGrid account - verify account

### Issue: "Invalid sender email"
**Solution:**
- `SENDGRID_FROM_EMAIL` must be verified in SendGrid dashboard
- Go to Settings → Sender Authentication
- Complete the verification process
- Wait a few minutes before testing again

---

## 📊 Email Templates

### Verification Email Template
- **Subject:** 📧 Verify Your Email Address - Chat Chat
- **Contains:** Username, verification button, backup link, 24-hour timer
- **Design:** Modern gradient header, clear call-to-action

### Recovery Email Template
- **Subject:** 🔐 Your Chat Chat Recovery ID
- **Contains:** Recovery ID, security question, usage instructions
- **Design:** Professional formatting, security warnings

---

## 🔒 Security Considerations

1. **API Key Protection:**
   - Never commit `.env` to version control
   - Store API key in environment variables only
   - Rotate keys regularly
   - Use separate keys for different environments

2. **Token Expiration:**
   - Email verification tokens expire after 24 hours
   - Recovery IDs persist but tokens are single-use
   - Implement rate limiting (already included: 100 req/15min)

3. **From Email:**
   - Use a noreply email address (no replies monitored)
   - Verify domain ownership in SendGrid
   - Enable DKIM/SPF for better deliverability

4. **Development vs Production:**
   - Set `NODE_ENV=development` to see tokens in API responses
   - Set `NODE_ENV=production` to hide sensitive information
   - Use separate SendGrid keys for each environment

---

## 🚀 Next Steps

1. ✅ Sign up for SendGrid account
2. ✅ Get API key and verified sender email
3. ✅ Add `SENDGRID_API_KEY` and `SENDGRID_FROM_EMAIL` to `.env`
4. ✅ Restart backend server
5. ✅ Test email endpoints
6. ✅ Deploy to production

---

## 📚 Useful Resources

- [SendGrid Documentation](https://docs.sendgrid.com/)
- [SendGrid Node.js Library](https://github.com/sendgrid/sendgrid-nodejs)
- [SendGrid SMS Integration](https://docs.sendgrid.com/for-developers/sending-email/api-overview)
- [Email Deliverability](https://docs.sendgrid.com/ui/sending-email/deliverability)

---

## 💬 Support

If you encounter issues:
1. Check SendGrid Activity Feed for error details
2. Review backend logs for error messages
3. Verify all environment variables are set correctly
4. Test API key in SendGrid dashboard settings
5. Check email templates for HTML syntax errors

---

**Last Updated:** 2026-04-01  
**SendGrid Package Version:** @sendgrid/mail (latest)
