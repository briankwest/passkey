import { body, param, query, validationResult, ValidationChain } from 'express-validator';
import { Request, Response, NextFunction } from 'express';

// Validation error handler
export const handleValidationErrors = (req: Request, res: Response, next: NextFunction) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ 
      error: 'Validation failed',
      details: errors.array() 
    });
  }
  next();
};

// Common validators
export const emailValidator = body('email')
  .isEmail()
  .normalizeEmail()
  .withMessage('Please provide a valid email address');

export const passwordValidator = body('password')
  .isLength({ min: 12 })
  .withMessage('Password must be at least 12 characters long')
  .isLength({ max: 128 })
  .withMessage('Password must not exceed 128 characters');

export const uuidValidator = (field: string) => 
  param(field)
    .isUUID()
    .withMessage(`${field} must be a valid UUID`);

// Auth validators
export const validateRegistration = [
  emailValidator,
  passwordValidator,
  body('passwordConfirm')
    .custom((value, { req }) => value === req.body.password)
    .withMessage('Passwords do not match'),
  body('firstName')
    .optional()
    .trim()
    .isLength({ min: 1, max: 50 })
    .escape(),
  body('lastName')
    .optional()
    .trim()
    .isLength({ min: 1, max: 50 })
    .escape(),
  handleValidationErrors
];

export const validateLogin = [
  emailValidator,
  body('password')
    .notEmpty()
    .withMessage('Password is required'),
  body('totpCode')
    .optional()
    .matches(/^[0-9]{6}$|^[A-Z0-9]{5}-[A-Z0-9]{5}$/)
    .withMessage('Invalid 2FA code format'),
  handleValidationErrors
];

export const validatePasswordReset = [
  body('token')
    .notEmpty()
    .isLength({ min: 32 })
    .withMessage('Invalid reset token'),
  passwordValidator,
  body('passwordConfirm')
    .custom((value, { req }) => value === req.body.password)
    .withMessage('Passwords do not match'),
  handleValidationErrors
];

export const validatePasswordChange = [
  body('currentPassword')
    .optional()
    .notEmpty()
    .withMessage('Current password is required when changing existing password'),
  body('newPassword')
    .isLength({ min: 12 })
    .withMessage('Password must be at least 12 characters long')
    .isLength({ max: 128 })
    .withMessage('Password must not exceed 128 characters')
    .custom((value, { req }) => {
      // Only check if different when currentPassword is provided
      if (req.body.currentPassword) {
        return value !== req.body.currentPassword;
      }
      return true;
    })
    .withMessage('New password must be different from current password'),
  handleValidationErrors
];

// Profile validators
export const validateProfileUpdate = [
  body('username')
    .optional()
    .trim()
    .isLength({ min: 3, max: 30 })
    .matches(/^[a-zA-Z0-9_-]+$/)
    .withMessage('Username must be 3-30 characters and contain only letters, numbers, underscores, and hyphens'),
  body('email')
    .optional()
    .isEmail()
    .normalizeEmail(),
  body('first_name')
    .optional()
    .trim()
    .isLength({ max: 50 })
    .escape(),
  body('last_name')
    .optional()
    .trim()
    .isLength({ max: 50 })
    .escape(),
  body('display_name')
    .optional()
    .trim()
    .isLength({ max: 100 })
    .escape(),
  body('bio')
    .optional()
    .trim()
    .isLength({ max: 500 })
    .escape(),
  handleValidationErrors
];

// TOTP validators
export const validateTOTPSetup = [
  body('totpCode')
    .matches(/^[0-9]{6}$/)
    .withMessage('TOTP code must be 6 digits'),
  handleValidationErrors
];

// WebAuthn validators
export const validateWebAuthnRegistration = [
  body('email')
    .optional()
    .isEmail()
    .normalizeEmail(),
  body('firstName')
    .optional()
    .trim()
    .escape(),
  body('lastName')
    .optional()
    .trim()
    .escape(),
  body('origin')
    .optional()
    .isURL({ require_tld: false }),
  handleValidationErrors
];

// Query validators
export const validateEmailCheck = [
  query('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Valid email required'),
  handleValidationErrors
];

// Sanitization helpers
export const sanitizeInput = (value: string): string => {
  return value
    .trim()
    .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
    .replace(/javascript:/gi, '')
    .replace(/on\w+\s*=/gi, '');
};

// Custom validation rules
export const isStrongPassword = (password: string): boolean => {
  // This is handled by zxcvbn in the password service
  // but we can add basic checks here
  return password.length >= 12;
};

// Rate limit specific validators
export const validateRateLimitByEmail = [
  emailValidator,
  handleValidationErrors
];