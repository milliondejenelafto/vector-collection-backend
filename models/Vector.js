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
    required: true,
  },
  description: {
    type: String,
  },
  fileName: {
    type: String,
    required: true,
  },
  fileUrl: {
    type: String,
    required: true,
  },
  category: {
    type: String,
    required: true,
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
    required: true,
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
    required: true,
  },
  license: {
    type: String,
    required: true,
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
