# 📤 Media Upload API Documentation

## Overview
The Media Upload API provides three endpoints for managing media content uploads (videos, photos, camera recordings) in the Connect App backend.

## Endpoints

### 1. POST `/api/upload/media`
**Upload media content with progress tracking**

#### Request
```
Method: POST
URL: /api/upload/media
Authentication: Required (Bearer token)
Content-Type: multipart/form-data
```

#### Request Body
```
file: File (binary)
fileName: string (optional)
fileType: string (required) - 'video', 'photo', or 'camera'
title: string (required)
description: string (optional)
chatId: string (optional) - MongoDB ObjectId for chat association
groupId: string (optional) - MongoDB ObjectId for group association
```

#### Response (Success - 201)
```json
{
  "success": true,
  "message": "Media uploaded successfully",
  "uploadId": "1707824456123-987654321",
  "fileUrl": "https://your-domain.com/uploads/media/1707824456123-987654321.mp4",
  "fileName": "my-video.mp4",
  "fileType": "video",
  "fileSize": 52428800
}
```

#### Response (Error - 400/500)
```json
{
  "success": false,
  "error": "Error message describing what went wrong"
}
```

#### Supported File Types
- **Images**: jpeg, jpg, png, gif
- **Videos**: mp4, mov, webm, avi, mkv, flv, wmv
- **Max File Size**: 500MB

#### Usage Example (Dart/Flutter)
```dart
final response = await http.post(
  Uri.parse('https://your-backend.com/api/upload/media'),
  headers: {
    'Authorization': 'Bearer $authToken',
    'Content-Type': 'application/json',
  },
  body: json.encode({
    'fileName': 'my_video.mp4',
    'fileType': 'video',
    'title': 'My First Video',
    'description': 'A video from my camera',
  }),
);
```

---

### 2. GET `/api/upload/progress/{uploadId}`
**Get current upload progress and status**

#### Request
```
Method: GET
URL: /api/upload/progress/{uploadId}
Authentication: Required (Bearer token)
```

#### Response (Success - 200)
```json
{
  "success": true,
  "uploadId": "1707824456123-987654321",
  "progress": {
    "bytesUploaded": 52428800,
    "totalBytes": 52428800,
    "percentComplete": 100,
    "status": "completed",
    "speed": 8388608,
    "remainingTime": 0,
    "startTime": "2024-02-13T10:34:16.123Z",
    "lastUpdateTime": "2024-02-13T10:34:22.456Z",
    "completedTime": "2024-02-13T10:34:22.456Z"
  },
  "mediaInfo": {
    "fileName": "my-video.mp4",
    "fileType": "video",
    "title": "My First Video",
    "fileUrl": "https://your-domain.com/uploads/media/1707824456123-987654321.mp4"
  }
}
```

#### Response (Error - 404/403)
```json
{
  "success": false,
  "error": "Upload not found" or "Access denied"
}
```

#### Status Values
- `pending` - Upload is queued
- `uploading` - Currently uploading
- `paused` - Upload is paused
- `completed` - Upload finished successfully
- `failed` - Upload failed
- `cancelled` - Upload was cancelled by user

#### Usage Example (Dart/Flutter)
```dart
final response = await http.get(
  Uri.parse('https://your-backend.com/api/upload/progress/$uploadId'),
  headers: {
    'Authorization': 'Bearer $authToken',
  },
);

final data = jsonDecode(response.body);
final percentComplete = data['progress']['percentComplete'];
final speed = data['progress']['speed']; // bytes per second
final remainingTime = data['progress']['remainingTime']; // seconds
```

---

### 3. POST `/api/upload/cancel/{uploadId}`
**Cancel an ongoing upload**

#### Request
```
Method: POST
URL: /api/upload/cancel/{uploadId}
Authentication: Required (Bearer token)
```

#### Response (Success - 200)
```json
{
  "success": true,
  "message": "Upload cancelled successfully",
  "uploadId": "1707824456123-987654321",
  "status": "cancelled"
}
```

#### Response (Error - 400/403/404)
```json
{
  "success": false,
  "error": "Error message"
}
```

#### Error Cases
- `400` - Upload already completed or already cancelled
- `403` - User not authorized to cancel this upload
- `404` - Upload not found

#### Usage Example (Dart/Flutter)
```dart
final response = await http.post(
  Uri.parse('https://your-backend.com/api/upload/cancel/$uploadId'),
  headers: {
    'Authorization': 'Bearer $authToken',
    'Content-Type': 'application/json',
  },
);
```

---

## Database Models

### MediaUpload Schema
Stores information about uploaded media files.

```javascript
{
  uploadId: String (unique),
  userId: ObjectId (ref: User),
  fileName: String,
  fileType: String,
  mimeType: String,
  fileSize: Number (in bytes),
  title: String,
  description: String,
  filePath: String,
  fileUrl: String,
  thumbnailUrl: String,
  duration: Number (seconds, for videos),
  uploadProgress: Number (0-100),
  status: String (pending|uploading|completed|failed|cancelled),
  chatId: ObjectId (ref: Chat),
  groupId: ObjectId (ref: Group),
  uploadedAt: Date,
  completedAt: Date,
  cancelledAt: Date,
  errorMessage: String,
  retryCount: Number,
  metadata: Map
}
```

### UploadProgress Schema
Tracks real-time upload progress for monitoring.

```javascript
{
  uploadId: String (unique),
  userId: ObjectId (ref: User),
  bytesUploaded: Number,
  totalBytes: Number,
  percentComplete: Number (0-100),
  status: String,
  speed: Number (bytes/s),
  remainingTime: Number (seconds),
  startTime: Date,
  lastUpdateTime: Date,
  completedTime: Date,
  errorMessage: String,
  chunks: [{
    chunkIndex: Number,
    size: Number,
    status: String,
    uploadedAt: Date
  }]
}
```

---

## Implementation Guide for Frontend

### Step 1: Update your API service

The Dart code you provided already has the correct implementation in the `uploadMediaContent` method. The backend now supports these three new endpoints.

### Step 2: Handle upload progress

```dart
// Upload with progress tracking
final result = await ApiService.uploadMediaContent(
  authToken: authToken,
  filePath: '/path/to/video.mp4',
  fileName: 'video.mp4',
  fileType: 'video',
  title: 'My Video',
  description: 'A test video',
  onProgress: (progress) {
    // progress is from 0.0 to 1.0
    print('Upload progress: ${(progress * 100).toStringAsFixed(1)}%');
  },
);

// Check upload progress
final progressData = await http.get(
  Uri.parse('$baseUrl/api/upload/progress/${result['uploadId']}'),
  headers: {'Authorization': 'Bearer $authToken'},
);

// Cancel upload if needed
await http.post(
  Uri.parse('$baseUrl/api/upload/cancel/${result['uploadId']}'),
  headers: {'Authorization': 'Bearer $authToken'},
);
```

### Step 3: Configuration

Ensure your backend is configured with the following:

**Environment Variables** (`.env` file):
```
MONGODB_URI=mongodb://localhost/connect-app
PORT=30001
JWT_SECRET=your-secret-key
```

**Directories** (created automatically):
- `uploads/` - Regular file uploads
- `uploads/media/` - Media content uploads

---

## Error Handling

### Common Errors

| Status | Error | Cause |
|--------|-------|-------|
| 400 | No file uploaded | File was not included in the request |
| 400 | Missing required fields | `fileType` or `title` not provided |
| 400 | Invalid fileType | Only 'video', 'photo', 'camera' allowed |
| 401 | Unauthorized | Missing or invalid auth token |
| 403 | Access denied | User not authorized to access/cancel upload |
| 404 | Upload not found | Invalid uploadId provided |
| 413 | Payload too large | File exceeds 500MB limit |
| 500 | Server error | Internal server error |

---

## Best Practices

1. **Always validate file type** before uploading
2. **Implement progress tracking** for better UX
3. **Cancel uploads** if user changes action
4. **Clean up orphaned uploads** with expired timestamps
5. **Use proper error handling** for network failures
6. **Implement retry logic** for failed uploads
7. **Set reasonable timeouts** (10-30 seconds for progress checks)

---

## Performance Considerations

- **Upload Timeout**: 30 seconds for initial chunk
- **File Size Limit**: 500MB for media, 10MB for regular files
- **Max Concurrent Uploads**: Handled by client-side logic
- **Storage**: Uploads stored in `uploads/media/` directory
- **Cleanup**: Cancelled uploads are deleted automatically

---

## Future Enhancements

Potential improvements for the media upload system:

1. **Chunked uploads** - Break large files into chunks
2. **Resume capability** - Resume interrupted uploads
3. **Video transcoding** - Auto-convert formats
4. **Thumbnail generation** - Auto-generate video thumbnails
5. **CDN integration** - Serve from content delivery network
6. **Compression** - Automatic image/video compression
7. **Virus scanning** - Scan uploaded files for malware
8. **Bandwidth limiting** - Rate limit uploads per user
9. **Storage quota** - Limit storage per user
10. **Metadata extraction** - Extract EXIF, duration, dimensions

---

## Testing

Use the provided test script or curl commands:

```bash
# Upload media
curl -X POST \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -F "file=@/path/to/video.mp4" \
  -F "fileType=video" \
  -F "title=Test Video" \
  http://localhost:30001/api/upload/media

# Check progress
curl -X GET \
  -H "Authorization: Bearer YOUR_TOKEN" \
  http://localhost:30001/api/upload/progress/UPLOAD_ID

# Cancel upload
curl -X POST \
  -H "Authorization: Bearer YOUR_TOKEN" \
  http://localhost:30001/api/upload/cancel/UPLOAD_ID
```

---

## Support

For issues or questions about the media upload API:
1. Check the error messages in the response
2. Review the database models for data structure
3. Ensure proper authentication with valid JWT token
4. Verify file types are supported
5. Check server logs for detailed error information

