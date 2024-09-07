const User = require('../models/user');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { body, validationResult } = require('express-validator');
const rateLimit = require('express-rate-limit');
const validator = require('validator');

console.log("JWT_SECRET:", process.env.JWT_SECRET);

// Register
exports.register = [
  body('name').not().isEmpty().withMessage('Name is required'),
  body('email').isEmail().withMessage('Enter a valid email'),
  
  body('password')
    .isLength({ min: 6 })
    .withMessage('Password must be at least 6 characters long')
    .matches(/[a-z]/).withMessage('Password must contain at least one lowercase letter')
    .matches(/[A-Z]/).withMessage('Password must contain at least one uppercase letter')
    .matches(/\d/).withMessage('Password must contain at least one digit')
    .matches(/[@$!%*?&#]/).withMessage('Password must contain at least one special character'),

  body('countryCode').not().isEmpty().withMessage('Country code is required'),
  body('mobile').isLength({ min: 10, max: 10 }).withMessage('Enter a valid 10-digit mobile number'),

  body('address.street').not().isEmpty().withMessage('Street address is required'),
  body('address.city').not().isEmpty().withMessage('City is required'),
  body('address.state').not().isEmpty().withMessage('State is required'),
  body('address.country').not().isEmpty().withMessage('Country is required'),
  body('address.zipCode').not().isEmpty().withMessage('ZipCode is required'),

  async (req, res) => {
    const { name, email, password, countryCode, mobile, address, role, dateOfBirth } = req.body;

    // Check for validation errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    if (!validator.isEmail(email)) {
      return res.status(400).json({ message: 'Invalid email format' });
    }

    try {
      let user = await User.findOne({ 
        $or: [{ email }, { countryCode, mobile }] 
      });
      if (user) {
        return res.status(400).json({ message: 'User with this email or mobile already exists' });
      }

      user = new User({
        name,
        email,
        password,
        mobile,
        countryCode,
        address,
        role,
        dateOfBirth
      });

      await user.save();

      const payload = {
        user: {
          id: user.id,
          role: user.role
        }
      };

      const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1h' });

      res.status(201).json({ token });
    } catch (error) {
      console.error(error.message);
      res.status(500).json({ message: 'Server error' });
    }
  }
];

//Login
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, 
  max: 5, 
  message: 'Too many login attempts, please try again later.',
  statusCode: 429
});

exports.login = [
  body('email').isEmail().withMessage('Enter a valid email'),
  body('password').not().isEmpty().withMessage('Password is required'),

  loginLimiter,

  async (req, res) => {
    const { email, password } = req.body;

    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    if (!validator.isEmail(email)) {
      return res.status(400).json({ message: 'Invalid email format' });
    }

    try {
      const user = await User.findOne({ email });
      if (!user) {
        return res.status(400).json({ message: 'Invalid credentials' }); 
      }

      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
        return res.status(400).json({ message: 'Invalid credentials' });
      }

      const payload = {
        user: { id: user.id, role: user.role }
      };

      const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1h' });

      const refreshToken = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '7d' });

      res.json({ token, refreshToken });

    } catch (error) {
      console.error(error.message);
      res.status(500).json({ message: 'Server error' });
    }
  }
];
