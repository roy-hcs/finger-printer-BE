const express = require('express');
const bcrypt = require('bcrypt');
const { db } = require('../db/database');
const { 
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse
} = require('@simplewebauthn/server');
const { webAuthnConfig } = require('../utils/webAuthnConfig');

const router = express.Router();
const SALT_ROUNDS = 10;

// User registration
router.post('/register', async (req, res, next) => {
  try {
    console.log('Received registration request:', req.body);
    const { username, password } = req.body;
    
    // Validate input
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required' });
    }
    
    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }
    
    // Check if username already exists
    db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
      if (err) {
        return next(err);
      }
      
      if (user) {
        return res.status(409).json({ error: 'Username already exists' });
      }
      
      // Hash the password
      const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
      
      // Insert new user
      db.run('INSERT INTO users (username, password) VALUES (?, ?)', 
        [username, hashedPassword], 
        function(err) {
          if (err) {
            return next(err);
          }
          
          return res.status(201).json({ 
            message: 'User registered successfully', 
            userId: this.lastID 
          });
        });
    });
  } catch (error) {
    next(error);
  }
});

// User login
router.post('/login', (req, res, next) => {
  try {
    const { username, password } = req.body;
    
    // Validate input
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required' });
    }
    
    // Find the user
    db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
      if (err) {
        return next(err);
      }
      
      if (!user) {
        return res.status(401).json({ error: 'Invalid username or password' });
      }
      
      // Compare passwords
      const passwordMatch = await bcrypt.compare(password, user.password);
      
      if (!passwordMatch) {
        return res.status(401).json({ error: 'Invalid username or password' });
      }
      
      // Login successful
      return res.status(200).json({ 
        message: 'Login successful',
        userId: user.id,
        username: user.username
      });
    });
  } catch (error) {
    next(error);
  }
});

// Generate registration options for WebAuthn
router.post('/generate-registration-options', (req, res, next) => {
  try {
    const { userId, username } = req.body;
    
    if (!userId || !username) {
      return res.status(400).json({ error: 'User ID and username are required' });
    }
    
    // Get existing credentials for this user (if any)
    db.all('SELECT * FROM authenticators WHERE user_id = ?', [userId], async (err, authenticators) => {
      if (err) {
        return next(err);
      }
      
      // Map authenticators to the format expected by SimpleWebAuthn
      const excludeCredentials = authenticators.map(auth => ({
        id: Buffer.from(auth.credential_id, 'base64url'),
        type: 'public-key',
        transports: auth.transports ? JSON.parse(auth.transports) : undefined,
      }));
      
      // Generate registration options
      const options = await generateRegistrationOptions({
        rpName: webAuthnConfig.rpName,
        rpID: webAuthnConfig.rpID,
        userID: userId.toString(),
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
      
      // Store challenge in the session or database for verification
      db.run('INSERT OR REPLACE INTO challenges (user_id, challenge, expires) VALUES (?, ?, ?)',
        [userId, options.challenge, Date.now() + 5 * 60 * 1000], // expires in 5 minutes
        (err) => {
          if (err) {
            return next(err);
          }
          
          return res.json(options);
        });
    });
  } catch (error) {
    next(error);
  }
});

// Verify WebAuthn registration
router.post('/verify-registration', (req, res, next) => {
  try {
    const { userId, attestationResponse } = req.body;
    
    if (!userId || !attestationResponse) {
      return res.status(400).json({ error: 'User ID and attestation response are required' });
    }
    
    // Get the challenge from the database
    db.get('SELECT challenge FROM challenges WHERE user_id = ? AND expires > ?', 
      [userId, Date.now()], 
      async (err, row) => {
        if (err) {
          return next(err);
        }
        
        if (!row) {
          return res.status(400).json({ error: 'Challenge not found or expired' });
        }
        
        const expectedChallenge = row.challenge;
        
        // Verify the registration response
        let verification;
        try {
          verification = await verifyRegistrationResponse({
            response: attestationResponse,
            expectedChallenge,
            expectedOrigin: webAuthnConfig.origin,
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
        
        db.run(
          'INSERT INTO authenticators (user_id, credential_id, public_key, counter, created_at) VALUES (?, ?, ?, ?, ?)',
          [userId, credentialIDBase64, credentialPublicKeyBase64, counter, Date.now()],
          (err) => {
            if (err) {
              return next(err);
            }
            
            // Clean up the challenge
            db.run('DELETE FROM challenges WHERE user_id = ?', [userId]);
            
            return res.json({ verified: true });
          }
        );
      });
  } catch (error) {
    next(error);
  }
});

// Generate authentication options for WebAuthn
router.post('/generate-authentication-options', (req, res, next) => {
  try {
    const { username } = req.body;
    
    if (!username) {
      return res.status(400).json({ error: 'Username is required' });
    }
    
    // Get the user
    db.get('SELECT id FROM users WHERE username = ?', [username], (err, user) => {
      if (err) {
        return next(err);
      }
      
      if (!user) {
        return res.status(404).json({ error: 'User not found' });
      }
      
      const userId = user.id;
      
      // Get authenticators for this user
      db.all('SELECT * FROM authenticators WHERE user_id = ?', [userId], async (err, authenticators) => {
        if (err) {
          return next(err);
        }
        
        if (!authenticators.length) {
          return res.status(404).json({ error: 'No authenticators found for this user' });
        }
        
        // Map authenticators to the format expected by SimpleWebAuthn
        const allowCredentials = authenticators.map(auth => ({
          id: Buffer.from(auth.credential_id, 'base64url'),
          type: 'public-key',
          transports: auth.transports ? JSON.parse(auth.transports) : undefined,
        }));
        
        // Generate authentication options
        const options = await generateAuthenticationOptions({
          rpID: webAuthnConfig.rpID,
          allowCredentials,
          userVerification: 'preferred',
        });
        
        // Store challenge in the database for verification
        db.run('INSERT OR REPLACE INTO challenges (user_id, challenge, expires) VALUES (?, ?, ?)',
          [userId, options.challenge, Date.now() + 5 * 60 * 1000], // expires in 5 minutes
          (err) => {
            if (err) {
              return next(err);
            }
            
            return res.json(options);
          });
      });
    });
  } catch (error) {
    next(error);
  }
});

// Verify WebAuthn authentication
router.post('/verify-authentication', (req, res, next) => {
  try {
    const { username, assertionResponse } = req.body;
    
    if (!username || !assertionResponse) {
      return res.status(400).json({ error: 'Username and assertion response are required' });
    }
    
    // Get the user
    db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
      if (err) {
        return next(err);
      }
      
      if (!user) {
        return res.status(404).json({ error: 'User not found' });
      }
      
      const userId = user.id;
      
      // Get the challenge
      db.get('SELECT challenge FROM challenges WHERE user_id = ? AND expires > ?',
        [userId, Date.now()],
        (err, challengeRow) => {
          if (err) {
            return next(err);
          }
          
          if (!challengeRow) {
            return res.status(400).json({ error: 'Challenge not found or expired' });
          }
          
          const expectedChallenge = challengeRow.challenge;
          
          // Get the authenticator
          const credentialIDBase64 = assertionResponse.id;
          
          db.get('SELECT * FROM authenticators WHERE credential_id = ?',
            [credentialIDBase64],
            async (err, authenticator) => {
              if (err) {
                return next(err);
              }
              
              if (!authenticator) {
                return res.status(404).json({ error: 'Authenticator not found' });
              }
              
              // Verify the authentication response
              let verification;
              try {
                verification = await verifyAuthenticationResponse({
                  response: assertionResponse,
                  expectedChallenge,
                  expectedOrigin: webAuthnConfig.origin,
                  expectedRPID: webAuthnConfig.rpID,
                  authenticator: {
                    credentialID: Buffer.from(authenticator.credential_id, 'base64url'),
                    credentialPublicKey: Buffer.from(authenticator.public_key, 'base64url'),
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
              db.run('UPDATE authenticators SET counter = ? WHERE credential_id = ?',
                [authenticationInfo.newCounter, credentialIDBase64],
                (err) => {
                  if (err) {
                    return next(err);
                  }
                  
                  // Clean up the challenge
                  db.run('DELETE FROM challenges WHERE user_id = ?', [userId]);
                  
                  // Authentication successful
                  return res.json({
                    verified: true,
                    userId: user.id,
                    username: user.username
                  });
                });
            });
        });
    });
  } catch (error) {
    next(error);
  }
});

// a simple health check endpoint
router.get('/health', (req, res) => {
  res.status(200).json({ status: 'OK', message: 'API is running' });
});

module.exports = router;
