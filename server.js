const express = require('express');
const mongoose = require('mongoose');
const passport = require('passport');
const session = require('express-session');
const MongoStore = require('connect-mongo'); 
const dotenv = require('dotenv');
const cors = require('cors');
const connectDB = require('./config/db');
const authRoutes = require('./routes/auth');
const appRoutes = require('./routes/app');

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

// Allowed origins
const allowedOrigins = ['https://main--glowing-sherbet-2fba6c.netlify.app'];

// CORS Middleware

app.use(cors({
  origin: allowedOrigins,
  credentials: true // Allow credentials (cookies, authorization headers, etc.)
}));

// Sessions
app.use(session({
  secret: process.env.SECRET,
  resave: false,
  saveUninitialized: true,  
  store: MongoStore.create({ mongoUrl: process.env.MONGO_URI,collectionName: 'sessions' }),
  cookie: {
    maxAge: 1000 * 60 * 60 * 24 * 7 // 1 week
  }
}));

// Passport middleware
app.use(passport.initialize());
app.use(passport.session());

// Routes
app.use('/auth', authRoutes);
app.use('/', appRoutes); // Add this line to use the main routes

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));