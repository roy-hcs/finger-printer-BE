const express = require('express');
const bcrypt = require('bcrypt');
const router = express.Router();
const { 
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse
} = require('@simplewebauthn/server');
// const {fromBase64URL} = require('../../utils/webauthn.js') 

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
    console.log('Request body received:', JSON.stringify(req.body));
    const { userId, attestationResponse, origin } = req.body;
    
    if (!userId || !attestationResponse) {
      return res.status(400).json({ error: 'User ID and attestation response are required' });
    }
    
    // Log the attestation response structure
    console.log('AttestationResponse structure:', 
      Object.keys(attestationResponse),
      'Response keys:', attestationResponse.response ? Object.keys(attestationResponse.response) : 'No response object'
    );
    
    // Get the challenge from database
    const expectedChallenge = db.getChallenge(userId);
    if (!expectedChallenge) {
      return res.status(400).json({ error: 'Challenge not found or expired' });
    }
    
    console.log('Challenge found:', expectedChallenge);
    
    // Verify the registration response
    let verification;
    try {
      // Use the allowed origins list instead of a single origin
      // Make sure expectedOrigin is properly formatted
      const expectedOrigin = origin || 
        (Array.isArray(webAuthnConfig.allowedOrigins) ? webAuthnConfig.allowedOrigins : [webAuthnConfig.origin]);
      
      console.log('Using expected origin:', expectedOrigin);
      console.log('Using expected rpID:', webAuthnConfig.rpID);
      
      verification = await verifyRegistrationResponse({
        response: attestationResponse,
        expectedChallenge,
        expectedOrigin,
        expectedRPID: webAuthnConfig.rpID,
        requireUserVerification: false,
      });
    } catch (error) {
      console.error('Verification error details:', error);
      return res.status(400).json({ error: error.message });
    }
    
    const { verified, registrationInfo } = verification;
    
    if (!verified || !registrationInfo) {
      return res.status(400).json({ error: 'Registration verification failed' });
    }
    
    console.log('Full registration info:', JSON.stringify(registrationInfo));
    
    // Extract credential data from the appropriate location based on the library version
    let credentialID, credentialPublicKey, counter;
    
    // SimpleWebAuthn v7+ structure
    if (registrationInfo.credentialID) {
      credentialID = registrationInfo.credentialID;
      credentialPublicKey = registrationInfo.credentialPublicKey;
      counter = registrationInfo.counter;
    } 
    // SimpleWebAuthn v6 and earlier structure
    else if (registrationInfo.credentialID === undefined && registrationInfo.aaguid) {
      // Extract from attestation data
      credentialID = Buffer.from(attestationResponse.id, 'base64url');
      credentialPublicKey = Buffer.from(attestationResponse.response.publicKey, 'base64');
      counter = 0; // Default initial counter
    }
    
    console.log('Extracted credential data:', {
      credentialIDExists: !!credentialID,
      credentialIDLength: credentialID ? credentialID.length : 0,
      publicKeyExists: !!credentialPublicKey,
      publicKeyLength: credentialPublicKey ? credentialPublicKey.length : 0
    });
    
    // Add additional safety checks when creating Buffers
    let credentialIDBase64 = null;
    let credentialPublicKeyBase64 = null;
    
    try {
      if (credentialID && credentialID.length > 0) {
        credentialIDBase64 = Buffer.from(credentialID).toString('base64url');
      } else if (attestationResponse.id) {
        // Direct fallback to the raw id from the response
        credentialIDBase64 = attestationResponse.id;
      }
      
      if (credentialPublicKey && credentialPublicKey.length > 0) {
        credentialPublicKeyBase64 = Buffer.from(credentialPublicKey).toString('base64url');
      } else if (attestationResponse.response && attestationResponse.response.publicKey) {
        // Direct fallback to the public key from the response
        credentialPublicKeyBase64 = attestationResponse.response.publicKey;
      }
    } catch (bufferError) {
      console.error('Buffer conversion error:', bufferError);
      return res.status(400).json({ 
        error: 'Failed to process credential data: ' + bufferError.message,
        details: {
          credentialIDType: typeof credentialID,
          publicKeyType: typeof credentialPublicKey
        }
      });
    }
    
    if (!credentialIDBase64 || !credentialPublicKeyBase64) {
      return res.status(400).json({ 
        error: 'Invalid credential data received from authenticator',
        credentialIDExists: !!credentialIDBase64,
        publicKeyExists: !!credentialPublicKeyBase64
      });
    }
    
    db.saveAuthenticator(userId, credentialIDBase64, credentialPublicKeyBase64, counter);
    
    // Clean up the challenge
    db.deleteChallenge(userId);
    
    res.json({ verified: true });
  } catch (error) {
    console.error('Server error in verify-registration:', error);
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

    // Map authenticators to allowCredentials format with correct ID format
    const allowCredentials = [];

    for (const auth of authenticators) {
      try {
        console.log('Processing credential:', {
          id: auth.credentialId,
          type: typeof auth.credentialId
        });

        // Skip invalid credential IDs
        if (!auth.credentialId || typeof auth.credentialId !== 'string') {
          console.error('Invalid credentialId:', auth.credentialId);
          continue;
        }

        // For SimpleWebAuthn server 7+, the ID should be a Uint8Array/Buffer
        // For earlier versions, it should be a base64url string
        // Let's try both approaches
        
        try {
          // First attempt - use the ID directly as a Base64URL string
          allowCredentials.push({
            id: auth.credentialId, // Keep as base64url string
            type: 'public-key',
            // Only add transports if available and valid
            ...(auth.transports ? { transports: JSON.parse(auth.transports) } : {})
          });
        } catch (strErr) {
          console.error('Error using string ID:', strErr);
          
          // Fallback - try as Buffer
          try {
            const rawCredentialId = Buffer.from(auth.credentialId, 'base64url');
            
            if (!Buffer.isBuffer(rawCredentialId) || rawCredentialId.length === 0) {
              console.error('Invalid buffer from credentialId:', auth.credentialId);
              continue;
            }
            
            allowCredentials.push({
              id: rawCredentialId,
              type: 'public-key',
              // Only add transports if available and valid
              ...(auth.transports ? { transports: JSON.parse(auth.transports) } : {})
            });
          } catch (bufErr) {
            console.error('Error using buffer ID:', bufErr);
          }
        }
      } catch (err) {
        console.error('Error processing credential:', err, auth);
      }
    }

    if (allowCredentials.length === 0) {
      return res.status(404).json({ error: 'No valid authenticators found for this user' });
    }

    console.log("Final allowCredentials:", allowCredentials.map(cred => ({
      idType: typeof cred.id,
      isBuffer: Buffer.isBuffer(cred.id),
      idLength: cred.id ? (Buffer.isBuffer(cred.id) ? cred.id.length : cred.id.length) : 0
    })));

    // Generate authentication options with the proper credential format
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
    console.error('Authentication options error:', error, error.stack);
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

    // Log authenticator details for debugging
    console.log('Found authenticator:', {
      id: authenticator.credentialId,
      hasPublicKey: !!authenticator.publicKey,
      hasCounter: 'counter' in authenticator,
      counterValue: authenticator.counter
    });
    
    // Add this to look at how we're storing the public key
    console.log('Raw public key from database:', authenticator.publicKey);
    
    // Convert the publicKey from base64url string to Uint8Array
    const publicKeyUint8Array = Buffer.from(authenticator.publicKey, 'base64url');
    console.log('is Unit8Array:', publicKeyUint8Array instanceof Uint8Array);
    // For v13.1.1, try a different approach to fix the credential error
    try {
      // Log the client origin for debugging
      const clientOrigin = origin || 'http://localhost:8080';
      console.log('Client origin:', clientOrigin);
      console.log('Allowed origins:', webAuthnConfig.allowedOrigins);
      
      // Convert stored authenticator data to the format expected by SimpleWebAuthn v13.1.1
      // In v13.1.1, the authenticator parameter in verifyAuthenticationResponse was renamed to credential
      const credential = {
        // These property names match what's expected by verifyAuthenticationResponse in v13.1.1
        id: authenticator.credentialId,
        // Use the converted Uint8Array publicKey
        publicKey: publicKeyUint8Array,
        // algorithm: 'ES256', // Default algorithm for WebAuthn
        counter: Number(authenticator.counter || 0),
      };
      
      console.log('Using credential data for v13.1.1:', {
        id: credential.id.substring(0, 10) + '...',
        publicKeyLength: credential.publicKey.length,
        isBuffer: Buffer.isBuffer(credential.publicKey),
        // algorithm: credential.algorithm,
        counter: credential.counter
      });
      
      // Verify authentication using the credential format for v13.1.1
      verification = await verifyAuthenticationResponse({
        response: assertionResponse,
        expectedChallenge: expectedChallenge,
        expectedOrigin: webAuthnConfig.allowedOrigins,
        expectedRPID: webAuthnConfig.rpID,
        // Pass credential directly as it's now correctly formatted for v13.1.1
        credential: credential,
        requireUserVerification: false,
      });
      
      console.log('Authentication verification succeeded!');
    } catch (error) {
      // Add detailed debugging info to identify the exact cause
      console.error('Authentication verification error:', error);
      console.error('Error stack:', error.stack);
      
      // Try to find clues in the assertion response
      console.log('Assertion response details:', {
        id: assertionResponse.id,
        type: assertionResponse.type,
        responseKeys: assertionResponse.response ? Object.keys(assertionResponse.response) : []
      });
      
      // Add origin information to the error response
      return res.status(400).json({ 
        error: 'Authentication verification failed: ' + error.message,
        details: 'Origin mismatch or credential format issue',
        requestOrigin: origin || 'Not provided',
        allowedOrigins: webAuthnConfig.allowedOrigins
      });
    }
    
    const { verified, authenticationInfo } = verification;
    
    if (!verified || !authenticationInfo) {
      return res.status(400).json({ error: 'Authentication verification failed' });
    }
    
    // Update the counter only if the authenticator supports it
    if ('counter' in authenticator) {
      db.updateAuthenticatorCounter(credentialIDBase64, authenticationInfo.newCounter);
    }
    
    // Clean up the challenge
    db.deleteChallenge(userId);
    
    // Authentication successful
    res.json({
      verified: true,
      userId: user.id,
      username: user.username
    });
  } catch (error) {
    console.error('Authentication error:', error);
    res.status(500).json({ error: error.message });
  }
});

module.exports = router;
