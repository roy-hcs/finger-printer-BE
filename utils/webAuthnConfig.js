/**
 * WebAuthn configuration settings
 */
require('dotenv').config();

const webAuthnConfig = {
  // Relying Party name - displayed to users during authentication
  rpName: 'Fingerprint MVP',
  
  // Relying Party ID must match the domain where the frontend is running
  // For GitHub Pages, use "roy-hcs.github.io" (domain only, no protocol or path)
  rpID: process.env.RPID || 'localhost',
  
  // Origin needs to allow both frontend and backend origins
  // Backend origin - for verifying responses
  origin: process.env.ORIGIN || 'http://localhost:3000',
  
  // List of allowed origins for cross-domain operations
  // This lets your backend verify WebAuthn responses from the frontend domain
  allowedOrigins: [
    process.env.ORIGIN || 'http://localhost:3000',
    process.env.FRONTEND_ORIGIN || 'http://localhost:8080'
  ]
};

module.exports = { webAuthnConfig };
