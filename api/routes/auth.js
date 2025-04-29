const express = require('express');
const bcrypt = require('bcrypt');
const router = express.Router();
const { 
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse
} = require('@simplewebauthn/server');

// Use our in-memory database
const db = require('../db');
const { webAuthnConfig } = require('../../utils/webAuthnConfig');

// Register endpoint
router.post('/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    // Validate input
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required' });
    }
    
    // Check if username already exists
    const existingUser = db.findUserByUsername(username);
    if (existingUser) {
      return res.status(409).json({ error: 'Username already exists' });
    }
    
    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // Create the user
    const newUser = db.createUser(username, hashedPassword);
    
    res.status(201).json({ 
      message: 'User registered successfully',
      userId: newUser.id
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Login endpoint
router.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    // Validate input
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required' });
    }
    
    // Find the user
    const user = db.findUserByUsername(username);
    if (!user) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }
    
    // Compare passwords
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }
    
    // Login successful
    res.status(200).json({ 
      message: 'Login successful',
      userId: user.id,
      username: user.username
    });
  } catch (error) {
    res.status(401).json({ error: 'Authentication failed' });
  }
});

// Generate registration options for WebAuthn
router.post('/generate-registration-options', async (req, res) => {
  try {
    const { userId, username } = req.body;
    
    if (!userId || !username) {
      return res.status(400).json({ error: 'User ID and username are required' });
    }
    
    // Get existing credentials for this user
    const authenticators = db.getAuthenticatorsByUserId(userId);
    
    // Map authenticators to the format expected by SimpleWebAuthn
    const excludeCredentials = authenticators.map(auth => ({
      id: Buffer.from(auth.credentialId, 'base64url'),
      type: 'public-key',
      transports: auth.transports ? JSON.parse(auth.transports) : undefined,
    }));
    
    // Convert userID to Uint8Array as required by SimpleWebAuthn
    const userIdUint8Array = new TextEncoder().encode(userId.toString());
    
    // Generate registration options
    const options = await generateRegistrationOptions({
      rpName: webAuthnConfig.rpName,
      rpID: webAuthnConfig.rpID,
      userID: userIdUint8Array, // Changed from string to Uint8Array
      userName: username,
      userDisplayName: username,
      attestationType: 'none',
      excludeCredentials,
      authenticatorSelection: {
        userVerification: 'preferred',
        residentKey: 'preferred',
      },
      supportedAlgorithmIDs: [-7, -257], // ES256 and RS256
    });
    
    // Store challenge in our in-memory database
    const expiryTime = Date.now() + 5 * 60 * 1000; // 5 minutes
    db.storeChallenge(userId, options.challenge, expiryTime);
    
    res.json(options);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Verify WebAuthn registration
router.post('/verify-registration', async (req, res) => {
  try {
    const { userId, attestationResponse, origin } = req.body;
    
    if (!userId || !attestationResponse) {
      return res.status(400).json({ error: 'User ID and attestation response are required' });
    }
    
    // Get the challenge from database
    const expectedChallenge = db.getChallenge(userId);
    if (!expectedChallenge) {
      return res.status(400).json({ error: 'Challenge not found or expired' });
    }
    
    // Verify the registration response
    let verification;
    try {
      // Use the allowed origins list instead of a single origin
      // This allows verification of responses from both frontend and backend
      verification = await verifyRegistrationResponse({
        response: attestationResponse,
        expectedChallenge,
        // Use either the client-provided origin or check against all allowed origins
        expectedOrigin: origin || webAuthnConfig.allowedOrigins,
        expectedRPID: webAuthnConfig.rpID,
        requireUserVerification: false,
      });
    } catch (error) {
      return res.status(400).json({ error: error.message });
    }
    
    const { verified, registrationInfo } = verification;
    
    if (!verified || !registrationInfo) {
      return res.status(400).json({ error: 'Registration verification failed' });
    }
    
    // Store the authenticator in the database
    const { credentialID, credentialPublicKey, counter } = registrationInfo;
    
    const credentialIDBase64 = Buffer.from(credentialID).toString('base64url');
    const credentialPublicKeyBase64 = Buffer.from(credentialPublicKey).toString('base64url');
    
    db.saveAuthenticator(userId, credentialIDBase64, credentialPublicKeyBase64, counter);
    
    // Clean up the challenge
    db.deleteChallenge(userId);
    
    res.json({ verified: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Generate authentication options for WebAuthn
router.post('/generate-authentication-options', async (req, res) => {
  try {
    const { username } = req.body;
    
    if (!username) {
      return res.status(400).json({ error: 'Username is required' });
    }
    
    // Get the user from the database
    const user = db.findUserByUsername(username);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    const userId = user.id;

    // Convert userID to Uint8Array to comply with SimpleWebAuthn requirements
    const userIdUint8Array = new TextEncoder().encode(userId.toString());

    // Retrieve authenticators for this user
    const authenticators = db.getAuthenticatorsByUserId(userId);

    if (!authenticators.length) {
      return res.status(404).json({ error: 'No authenticators found for this user' });
    }

    // Map authenticators to allowCredentials format
    const allowCredentials = authenticators.map(auth => ({
      id: Buffer.from(auth.credentialId, 'base64url'),
      type: 'public-key',
      transports: auth.transports ? JSON.parse(auth.transports) : undefined,
    }));

    // Generate authentication options
    const options = await generateAuthenticationOptions({
      rpID: webAuthnConfig.rpID,
      userVerification: 'preferred',
      allowCredentials,
    });

    // Store challenge in database for verification
    const expiryTime = Date.now() + 5 * 60 * 1000; // 5 minutes
    db.storeChallenge(userId, options.challenge, expiryTime);

    res.json(options);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Verify WebAuthn authentication
router.post('/verify-authentication', async (req, res) => {
  try {
    const { username, assertionResponse, origin } = req.body;
    
    if (!username || !assertionResponse) {
      return res.status(400).json({ error: 'Username and assertion response are required' });
    }
    
    // Get the user
    const user = db.findUserByUsername(username);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    const userId = user.id;
    
    // Get the challenge
    const expectedChallenge = db.getChallenge(userId);
    if (!expectedChallenge) {
      return res.status(400).json({ error: 'Challenge not found or expired' });
    }
    
    // Get the authenticator
    const credentialIDBase64 = assertionResponse.id;
    const authenticator = db.getAuthenticatorByCredentialId(credentialIDBase64);
    
    if (!authenticator) {
      return res.status(404).json({ error: 'Authenticator not found' });
    }
    
    // Verify the authentication response
    let verification;
    try {
      verification = await verifyAuthenticationResponse({
        response: assertionResponse,
        expectedChallenge,
        // Use either the client-provided origin or check against all allowed origins
        expectedOrigin: origin || webAuthnConfig.allowedOrigins,
        expectedRPID: webAuthnConfig.rpID,
        authenticator: {
          credentialID: Buffer.from(authenticator.credentialId, 'base64url'),
          credentialPublicKey: Buffer.from(authenticator.publicKey, 'base64url'),
          counter: authenticator.counter,
        },
        requireUserVerification: false,
      });
    } catch (error) {
      return res.status(400).json({ error: error.message });
    }
    
    const { verified, authenticationInfo } = verification;
    
    if (!verified || !authenticationInfo) {
      return res.status(400).json({ error: 'Authentication verification failed' });
    }
    
    // Update the counter
    db.updateAuthenticatorCounter(credentialIDBase64, authenticationInfo.newCounter);
    
    // Clean up the challenge
    db.deleteChallenge(userId);
    
    // Authentication successful
    res.json({
      verified: true,
      userId: user.id,
      username: user.username
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

module.exports = router;
