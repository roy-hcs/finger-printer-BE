/**
 * WebAuthn configuration settings
 */
require('dotenv').config();

const webAuthnConfig = {
  rpName: 'Fingerprint MVP',  
  rpID: process.env.WEBAUTHN_RP_ID || 'localhost',  
  origin: process.env.WEBAUTHN_ORIGIN || ['http://localhost:3000', 'http://localhost:8080'],
  timeout: 60000
};

module.exports = { webAuthnConfig };
