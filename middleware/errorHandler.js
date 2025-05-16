const { logError } = require('../utils/errorLogger');

const errorHandler = (err, req, res, next) => {
    // Log the error
    logError(err, req);

    // Don't expose internal server errors to user
    const statusCode = err.statusCode || 500;
    const message = statusCode === 500 ? 'Internal Server Error' : err.message;

    res.status(statusCode).json({
        status: 'error',
        message,
        errorId: new Date().getTime() // To help correlate with server logs
    });
};

module.exports = errorHandler;
