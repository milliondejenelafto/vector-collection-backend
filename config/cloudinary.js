const cloudinary = require('cloudinary').v2;
const dotenv = require('dotenv');
const https = require('https');

dotenv.config();

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

// Test the connection by uploading a small image
cloudinary.uploader.upload("https://res.cloudinary.com/demo/image/upload/sample.jpg", function(error, result) {
  if (error) {
    console.error('Cloudinary connection error:', error);
  } else {
    console.log('Cloudinary connected successfully:', result.url);
  }
});

module.exports = cloudinary;
