/**
 * WebAuthn configuration settings
 */
require('dotenv').config();

// For cross-origin setups, this must be the domain of your API server
const webAuthnConfig = {
  rpName: 'Fingerprint MVP',
  rpID: process.env.WEBAUTHN_RP_ID || 'roy123.xyz',
  // Include both your frontend and backend origins
  origin: [
    'https://roy-hcs.github.io',  // Frontend
    'https://roy123.xyz'          // Backend
  ],
  timeout: 60000
};

module.exports = { webAuthnConfig };
