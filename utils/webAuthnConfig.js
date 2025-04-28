/**
 * WebAuthn configuration settings
 */
require('dotenv').config();

const webAuthnConfig = {
  // Relying Party name - displayed to users during authentication
  rpName: 'Fingerprint MVP',
  
  // Relying Party ID - should be the domain, excluding protocol and port
  // In development, you can use 'localhost'
  rpID: process.env.RPID || 'localhost',
  
  // Origin of your application - should match your domain
  // For localhost development: 'http://localhost:3000' (include protocol and port)
  origin: process.env.ORIGIN || 'http://localhost:3000'
};

module.exports = { webAuthnConfig };
