const express = require('express');
const cors = require('cors');
const userRoutes = require('./routes/userRoutes');
const db = require('./db/database');

const app = express();
const PORT = process.env.PORT || 3000;

// Initialize the database
db.initDb();

// Middleware
app.use(cors());
app.use(express.json());

// Routes
app.use('/api/users', userRoutes);

// Simple test route
app.get('/', (req, res) => {
  res.json({ message: 'API is running' });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ 
    error: 'Something went wrong!',
    message: err.message
  });
});

// Start the server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
