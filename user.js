const mongoose = require('mongoose');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');

const userSchema = new mongoose.Schema({
  email: {
    type: String,
    unique: true,
    required: true,
    lowercase: true,
    trim: true,
    // Email validation to ensure proper format
    match: [/^\S+@\S+\.\S+$/, 'Please use a valid email address']
  },
  name: {
    type: String,
    required: true,
    trim: true
  },
  hash: String,
  salt: String,
});

/*
  setPassword()
  Generates a secure salt and hash for storing the user's password.
  Enhancement: Increased hashing iterations for stronger security.
*/
userSchema.methods.setPassword = function (password) {

  // Basic password strength validation
  if (password.length < 8) {
    throw new Error('Password must be at least 8 characters long');
  }

  // Generate random salt
  this.salt = crypto.randomBytes(16).toString('hex');

  // Generate password hash using PBKDF2
  // Enhancement: Increased iterations from 1000 → 10000 for stronger protection
  this.hash = crypto
    .pbkdf2Sync(password, this.salt, 10000, 64, 'sha512')
    .toString('hex');
};

/*
  validPassword()
  Compares an entered password with the stored hash.
*/
userSchema.methods.validPassword = function (password) {
  const hash = crypto
    .pbkdf2Sync(password, this.salt, 10000, 64, 'sha512')
    .toString('hex');

  return this.hash === hash;
};

/*
  generateJWT()
  Generates a secure authentication token for the user.
*/
userSchema.methods.generateJWT = function () {
  return jwt.sign(
    {
      _id: this._id,
      email: this.email,
      name: this.name,
    },
    process.env.JWT_SECRET,
    {
      expiresIn: '1h', // Token expires after 1 hour for security
    }
  );
};

const User = mongoose.model('users', userSchema);
module.exports = User;