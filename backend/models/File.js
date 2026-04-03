const mongoose = require('mongoose');

const fileSchema = new mongoose.Schema({
  filename: { type: String, required: true, unique: true }, // The name on disk
  originalName: { type: String, required: true },
  mimetype: { type: String, required: true },
  size: { type: Number, required: true },
  url: { type: String, required: true },
  uploadedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  chatId: { type: mongoose.Schema.Types.ObjectId, ref: 'Chat', index: true },
  createdAt: { type: Date, default: Date.now }
});

fileSchema.index({ filename: 1 });

module.exports = mongoose.model('File', fileSchema);