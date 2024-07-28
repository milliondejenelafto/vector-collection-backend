const multer = require('multer');
const { CloudinaryStorage } = require('multer-storage-cloudinary');
const cloudinary = require('../config/cloudinary');

// Configure Cloudinary storage
const storage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: {
    folder: 'vectors',
    resource_type: 'raw', // 'raw' to handle various file types
    public_id: (req, file) => file.originalname.replace(/\..+$/, ''), // Use original name without extension as public ID
  },
});

// Multer setup with file filter
const upload = multer({
  storage: storage,
  fileFilter: (req, file, cb) => {
    const validTypes = [
      'image/svg+xml', 
      'application/postscript', 
      'application/pdf', 
      'application/illustrator',
      'image/png', // Add png to allow raster image
      'image/jpeg' // Add jpeg/jpg to allow raster image
    ];

    if (validTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      console.error(`Unsupported file type: ${file.mimetype}`);
      cb(new Error('Unsupported file type. Only vector files are allowed.'), false);
    }
  }
});

// Middleware export
module.exports = upload;
