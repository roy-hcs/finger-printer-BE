// Simple in-memory database for Vercel deployment
// Note: This is only for demonstration and will reset on each deployment

const inMemoryDb = {
  users: [],
  authenticators: [],
  challenges: []
};

// User functions
const findUserByUsername = (username) => {
  return inMemoryDb.users.find(user => user.username === username) || null;
};

const createUser = (username, password) => {
  const newUser = {
    id: Date.now().toString(), // Simple ID generation
    username,
    password
  };
  inMemoryDb.users.push(newUser);
  return newUser;
};

const getUserById = (userId) => {
  return inMemoryDb.users.find(user => user.id === userId) || null;
};

// Authenticator functions
const getAuthenticatorsByUserId = (userId) => {
  return inMemoryDb.authenticators.filter(auth => auth.userId === userId);
};

const getAuthenticatorByCredentialId = (credentialId) => {
  return inMemoryDb.authenticators.find(auth => auth.credentialId === credentialId) || null;
};

const saveAuthenticator = (userId, credentialId, publicKey, counter) => {
  const newAuth = {
    userId,
    credentialId,
    publicKey,
    counter,
    createdAt: Date.now()
  };
  inMemoryDb.authenticators.push(newAuth);
  return newAuth;
};

const updateAuthenticatorCounter = (credentialId, newCounter) => {
  const auth = inMemoryDb.authenticators.find(a => a.credentialId === credentialId);
  if (auth) {
    auth.counter = newCounter;
    return true;
  }
  return false;
};

// Challenge functions
const storeChallenge = (userId, challenge, expiryTime) => {
  // Clean up old challenges first
  inMemoryDb.challenges = inMemoryDb.challenges.filter(
    c => c.userId !== userId && c.expiryTime > Date.now()
  );
  
  const newChallenge = {
    userId,
    challenge,
    expiryTime
  };
  inMemoryDb.challenges.push(newChallenge);
  return newChallenge;
};

const getChallenge = (userId) => {
  const challenge = inMemoryDb.challenges.find(
    c => c.userId === userId && c.expiryTime > Date.now()
  );
  return challenge ? challenge.challenge : null;
};

const deleteChallenge = (userId) => {
  inMemoryDb.challenges = inMemoryDb.challenges.filter(c => c.userId !== userId);
  return true;
};

module.exports = {
  findUserByUsername,
  createUser,
  getUserById,
  getAuthenticatorsByUserId,
  getAuthenticatorByCredentialId,
  saveAuthenticator,
  updateAuthenticatorCounter,
  storeChallenge,
  getChallenge,
  deleteChallenge,
  // Export the raw db for debugging only
  _db: inMemoryDb
};
