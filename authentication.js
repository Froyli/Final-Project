const User = require('../models/user');
const passport = require('passport');

/**
 * Normalize text input safely.
 * This helps keep stored data clean and consistent.
 */
const normalizeText = (value) => {
  return typeof value === 'string' ? value.trim() : '';
};

/**
 * Validate email format.
 */
const isValidEmail = (email) => {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
};

/**
 * Validate password strength.
 * Requirements:
 * - at least 8 characters
 * - at least 1 uppercase letter
 * - at least 1 lowercase letter
 * - at least 1 number
 */
const isStrongPassword = (password) => {
  const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$/;
  return passwordRegex.test(password);
};

/**
 * Register a new user.
 * Enhancements:
 * - modular validation
 * - normalized input
 * - stronger password rules
 * - duplicate-user protection
 * - consistent API responses
 */
const register = async (req, res) => {
  try {
    const rawName = req.body.name;
    const rawEmail = req.body.email;
    const rawPassword = req.body.password;

    const name = normalizeText(rawName);
    const email = normalizeText(rawEmail).toLowerCase();
    const password = typeof rawPassword === 'string' ? rawPassword : '';

    // Required field validation
    if (!name || !email || !password) {
      return res.status(400).json({
        success: false,
        message: 'Name, email, and password are required.',
      });
    }

    // Email validation
    if (!isValidEmail(email)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid email format.',
      });
    }

    // Password validation
    if (!isStrongPassword(password)) {
      return res.status(400).json({
        success: false,
        message:
          'Password must be at least 8 characters and include uppercase, lowercase, and a number.',
      });
    }

    // Check for duplicate user
    const existingUser = await User.findOne({ email });

    if (existingUser) {
      return res.status(409).json({
        success: false,
        message: 'User already exists.',
      });
    }

    // Create and save new user
    const user = new User({
      name,
      email,
    });

    user.setPassword(password);

    const savedUser = await user.save();
    const token = savedUser.generateJWT();

    return res.status(201).json({
      success: true,
      message: 'User registered successfully.',
      token,
    });
  } catch (err) {
    console.error('Register error:', err);

    return res.status(500).json({
      success: false,
      message: 'Registration failed due to server error.',
    });
  }
};

/**
 * Log in an existing user.
 * Enhancements:
 * - normalized email input
 * - clearer failed-login handling
 * - consistent response structure
 */
const login = (req, res) => {
  const rawEmail = req.body.email;
  const rawPassword = req.body.password;

  const email = normalizeText(rawEmail).toLowerCase();
  const password = typeof rawPassword === 'string' ? rawPassword : '';

  if (!email || !password) {
    return res.status(400).json({
      success: false,
      message: 'Email and password are required.',
    });
  }

  return passport.authenticate('local', (err, user, info) => {
    if (err) {
      console.error('Authentication error:', err);

      return res.status(500).json({
        success: false,
        message: 'Authentication error.',
      });
    }

    if (!user) {
      return res.status(401).json({
        success: false,
        message: info?.message || 'Invalid login credentials.',
      });
    }

    const token = user.generateJWT();

    return res.status(200).json({
      success: true,
      message: 'Login successful.',
      token,
    });
  })(req, res);
};

module.exports = {
  register,
  login,
};