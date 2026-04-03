const express = require('express');
const router = express.Router();
const { body } = require('express-validator');
const authController = require('../controllers/authController');

// ✅ ตัวแปล Validator ดึงมาจาก server.js เดิม
const validateRegistration = [
  body('username')
    .isLength({ min: 3, max: 30 })
    .withMessage('Username must be between 3-30 characters')
    .trim()
    .escape(),
  body('email')
    .isEmail()
    .withMessage('Must be a valid email')
    .normalizeEmail(),
  body('password')
    .isLength({ min: 6 })
    .withMessage('Password must be at least 6 characters'),
  body('pdpa_consent')
    .isBoolean()
    .withMessage('PDPA consent must be a boolean value')
    .equals('true')
    .withMessage('PDPA consent is required for registration')
];

const validateLogin = [
  body('email')
    .isEmail()
    .withMessage('Must be a valid email')
    .normalizeEmail(),
  body('password')
    .notEmpty()
    .withMessage('Password is required')
];

router.post('/register', validateRegistration, authController.register);
router.post('/login', validateLogin, authController.login);

module.exports = router;