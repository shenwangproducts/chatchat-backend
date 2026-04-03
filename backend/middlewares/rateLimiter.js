const rateLimit = require('express-rate-limit');

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  limit: 100, // limit each IP to 100 requests per windowMs
  handler: (req, res, next, options) => {
    res.status(options.statusCode).json({
      success: false,
      error: 'Too many requests from this IP, please try again later.'
    });
  }
});

module.exports = { limiter };