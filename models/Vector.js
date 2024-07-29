const mongoose = require('mongoose');
const { Schema } = mongoose;

const VectorSchema = new Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
  },
  title: {
    type: String,
  },
  description: {
    type: String,
  },
  fileName: {
    type: String,
  },
  fileUrl: {
    type: String,
  },
  category: {
    type: String,
  },
  subcategory: {
    type: String,
  },
  culture: {
    type: String,
  },
  culturalSignificance: {
    type: String,
  },
  fileFormat: {
    type: String,
  },
  fileSize: {
    type: String,
  },
  dimensions: {
    type: String,
  },
  tags: {
    type: [String],
  },
  labels: {
    type: [String],
  },
  author: {
    type: String,
  },
  license: {
    type: String,
  },
  usageScenarios: {
    type: String,
  },
  accessibility: {
    type: String,
  },
  status: {
    type: String,
    enum: ['pending', 'approved', 'rejected'],
    default: 'pending',
  },
  adminNotes: {
    type: String,
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
  updatedAt: {
    type: Date,
    default: Date.now,
  },
});

const Vector = mongoose.model('Vector', VectorSchema);
module.exports = Vector;
