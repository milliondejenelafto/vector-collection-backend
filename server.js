const express = require('express');
const mongoose = require('mongoose');
const passport = require('passport');
const dotenv = require('dotenv');
const cors = require('cors');
const connectDB = require('./config/db');
const authRoutes = require('./routes/auth');
const appRoutes = require('./routes/app');
const cookieParser = require('cookie-parser'); // Import cookie-parser

dotenv.config();

// Initialize Passport strategies
require('./config/passport-google')(passport);
require('./config/passport-local')(passport);

const app = express();

// Connect to MongoDB
connectDB();

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser()); // Use cookie-parser middleware

// Allowed origins
const allowedOrigins = ['https://main--glowing-sherbet-2fba6c.netlify.app', 'http://localhost:8000'];

// CORS Middleware
app.use(cors({
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps, curl requests)
    if (!origin) return callback(null, true);
    if (allowedOrigins.indexOf(origin) === -1) {
      const msg = 'The CORS policy for this site does not allow access from the specified Origin.';
      return callback(new Error(msg), false);
    }
    return callback(null, true);
  },
  credentials: true // Allow credentials (cookies, authorization headers, etc.)
}));

// Passport middleware
app.use(passport.initialize());

// Routes
app.use('/auth', authRoutes);
app.use('/', appRoutes); // Add this line to use the main routes

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
