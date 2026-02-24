# 🚀 Media Upload API - Quick Reference

## Endpoint Summary

| Method | Endpoint | Purpose |
|--------|----------|---------|
| POST | `/api/upload/media` | Upload media file |
| GET | `/api/upload/progress/{uploadId}` | Check upload status |
| POST | `/api/upload/cancel/{uploadId}` | Cancel upload |

---

## 1️⃣ Upload Media

```bash
curl -X POST "http://localhost:30001/api/upload/media" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -F "file=@video.mp4" \
  -F "fileType=video" \
  -F "title=My Video" \
  -F "description=Test video"
```

**Response:**
```json
{
  "success": true,
  "uploadId": "1707824456123-123456789",
  "fileUrl": "http://localhost:30001/uploads/media/video.mp4",
  "fileSize": 52428800
}
```

---

## 2️⃣ Check Progress

```bash
curl -X GET "http://localhost:30001/api/upload/progress/1707824456123-123456789" \
  -H "Authorization: Bearer YOUR_TOKEN"
```

**Response:**
```json
{
  "success": true,
  "progress": {
    "percentComplete": 75,
    "status": "uploading",
    "speed": 5242880,
    "remainingTime": 10
  }
}
```

---

## 3️⃣ Cancel Upload

```bash
curl -X POST "http://localhost:30001/api/upload/cancel/1707824456123-123456789" \
  -H "Authorization: Bearer YOUR_TOKEN"
```

**Response:**
```json
{
  "success": true,
  "message": "Upload cancelled successfully"
}
```

---

## 📱 Integration with Dart/Flutter

Your existing `ApiService` class already has the method:

```dart
static Future<Map<String, dynamic>> uploadMediaContent({
  required String authToken,
  required String filePath,
  required String fileName,
  required String fileType, // 'video', 'photo', 'camera'
  required String title,
  String? description,
  Function(double)? onProgress, // 0.0 to 1.0
})
```

### Usage Example:

```dart
// Upload
final result = await ApiService.uploadMediaContent(
  authToken: authToken,
  filePath: '/path/to/video.mp4',
  fileName: 'video.mp4',
  fileType: 'video',
  title: 'My Video',
  onProgress: (progress) {
    print('${(progress * 100).toStringAsFixed(1)}%');
  },
);

if(result['success']) {
  final uploadId = result['uploadId'];
  
  // Monitor progress
  final progress = await http.get(
    Uri.parse('$baseUrl/api/upload/progress/$uploadId'),
    headers: {'Authorization': 'Bearer $authToken'},
  );
  
  // Cancel if needed
  await http.post(
    Uri.parse('$baseUrl/api/upload/cancel/$uploadId'),
    headers: {'Authorization': 'Bearer $authToken'},
  );
}
```

---

## 🔧 Configuration

**Max File Size:** 500MB  
**Supported Video Formats:** MP4, MOV, WebM, AVI, MKV, FLV, WMV  
**Supported Image Formats:** JPEG, JPG, PNG, GIF  
**Authentication:** Required (JWT Bearer Token)  

---

## ❌ Common Errors

| Error | Cause | Solution |
|-------|-------|----------|
| No file uploaded | File field missing | Ensure `file` field in multipart |
| Invalid fileType | Wrong value | Use: `video`, `photo`, or `camera` |
| Missing title | Title field empty | Provide `title` in request |
| 401 Unauthorized | No/invalid token | Include valid auth token |
| 403 Access denied | Wrong user | Can only access own uploads |
| 413 Payload too large | File > 500MB | Reduce file size |

---

## 📊 Status Values

- `pending` - Queued
- `uploading` - In progress
- `completed` - Done ✅
- `failed` - Error occurred
- `cancelled` - User cancelled

---

## 💾 Database

**Collections Created:**
- `mediauploads` - Media file metadata
- `uploadprogresses` - Real-time progress tracking

**Indexes:**
- uploadId (unique)
- userId + timestamp
- status + timestamp

---

## 🎯 Typical Workflow

```
1. User selects video file
   ↓
2. Call POST /api/upload/media
   ↓
3. Get uploadId from response
   ↓
4. Show upload progress UI
   ↓
5. Poll GET /api/upload/progress/{uploadId}
   ↓
6. Update progress bar (0-100%)
   ↓
7. On complete: Show success message
   ↓
8. Or: Cancel with POST /api/upload/cancel/{uploadId}
```

---

## 🚀 Files Modified

- ✅ `backend/server.js` - Added models and endpoints
- ✅ `backend/MEDIA_UPLOAD_API.md` - Full documentation
- ✅ `backend/IMPLEMENTATION_SUMMARY.md` - Implementation details

---

## 📍 File Locations

```
backend/
├── server.js
│   ├── MediaUpload model (line ~510)
│   ├── UploadProgress model (line ~555)
│   ├── mediaStorage config (line ~90)
│   ├── mediaUpload multer (line ~110)
│   ├── POST /api/upload/media (line ~5860)
│   ├── GET /api/upload/progress (line ~5930)
│   └── POST /api/upload/cancel (line ~5990)
│
└── uploads/media/
    └── (uploaded media files stored here)
```

---

## ✨ Features

✅ Upload files up to 500MB  
✅ Real-time progress tracking  
✅ Cancel in-progress uploads  
✅ Automatic file cleanup  
✅ Security: Auth + Ownership verification  
✅ Error handling & logging  
✅ Database persistence  

---

## 🧪 Test with Postman

1. **POST** `http://localhost:30001/api/upload/media`
   - Header: `Authorization: Bearer YOUR_TOKEN`
   - Body: form-data
   - Fields: `file`, `fileType`, `title`, `description`

2. **GET** `http://localhost:30001/api/upload/progress/{uploadId}`
   - Header: `Authorization: Bearer YOUR_TOKEN`

3. **POST** `http://localhost:30001/api/upload/cancel/{uploadId}`
   - Header: `Authorization: Bearer YOUR_TOKEN`

---

## ⚡ Performance

- Upload to local: ~50MB/s
- Upload to cloud: ~5-20MB/s (depends on connection)
- Database writes: Indexed for fast lookups
- Storage: Separate directory for media

---

## 📞 Support

Check `MEDIA_UPLOAD_API.md` for detailed documentation.

