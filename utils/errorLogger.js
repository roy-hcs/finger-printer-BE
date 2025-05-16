const fs = require('fs');
const path = require('path');

const logDir = path.join(__dirname, '../logs');
const errorLogPath = path.join(logDir, 'error.log');
const inputLogPath = path.join(logDir, 'input.log');

// Ensure log directory exists
if (!fs.existsSync(logDir)) {
    fs.mkdirSync(logDir);
}

const logError = (error, req = null) => {
    const timestamp = new Date().toISOString();
    const errorLog = {
        timestamp,
        error: error.message,
        stack: error.stack,
        path: req ? req.path : 'N/A',
        method: req ? req.method : 'N/A'
    };
    
    fs.appendFileSync(errorLogPath, JSON.stringify(errorLog) + '\n');
};

const logInput = (req) => {
    const timestamp = new Date().toISOString();
    const inputLog = {
        timestamp,
        path: req.path,
        method: req.method,
        body: req.body,
        query: req.query,
        params: req.params
    };
    
    fs.appendFileSync(inputLogPath, JSON.stringify(inputLog) + '\n');
};

module.exports = { logError, logInput };
