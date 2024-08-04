const GoogleStrategy = require('passport-google-oauth20').Strategy;
const mongoose = require('mongoose');
const User = require('../models/User');
const { generateToken } = require('../utils/jwt');

module.exports = function(passport) {
  passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: '/auth/google/callback',
  }, async (token, tokenSecret, profile, done) => {
    const newUser = {
      googleId: profile.id,
      displayName: profile.displayName,
      email: profile.emails && profile.emails[0].value ? profile.emails[0].value : '',
      image: profile.photos && profile.photos[0].value ? profile.photos[0].value : ''
    };

    try {
      let user = await User.findOne({ googleId: profile.id });

      if (user) {
        const jwtToken = generateToken(user);
        user.token = jwtToken; // Assign the JWT token
        return done(null, user);
      } else {
        user = await User.create(newUser);
        const jwtToken = generateToken(user);
        user.token = jwtToken; // Assign the JWT token
        return done(null, user);
      }
    } catch (err) {
      console.error(err);
      return done(err, null);
    }
  }));

  passport.serializeUser((user, done) => {
    done(null, user.id);
  });

  passport.deserializeUser(async (id, done) => {
    try {
      const user = await User.findById(id);
      done(null, user);
    } catch (err) {
      done(err, null);
    }
  });
};
