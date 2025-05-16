/**
 * WebAuthn configuration settings
 */
require('dotenv').config();

const webAuthnConfig = {
  rpName: 'Fingerprint MVP',  
  rpID: process.env.WEBAUTHN_RP_ID || 'localhost',
  // Ensure origin is always an array for proper WebAuthn verification
  origin: Array.isArray(process.env.WEBAUTHN_ORIGIN) 
    ? process.env.WEBAUTHN_ORIGIN 
    : (process.env.WEBAUTHN_ORIGIN ? [process.env.WEBAUTHN_ORIGIN] : ['http://localhost:3000', 'http://localhost:8080']),
  timeout: 60000
};

module.exports = { webAuthnConfig };
