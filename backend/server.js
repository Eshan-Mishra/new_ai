import express from 'express';
import cors from 'cors';
import { createObjectCsvWriter } from 'csv-writer';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import fs from 'fs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = 3000;

// Middleware
app.use(cors());
app.use(express.json());

// Ensure users.csv exists
const csvFilePath = join(__dirname, 'users.csv');
if (!fs.existsSync(csvFilePath)) {
  fs.writeFileSync(csvFilePath, 'email,password\n');
}

// CSV Writer setup
const csvWriter = createObjectCsvWriter({
  path: csvFilePath,
  header: [
    { id: 'email', title: 'email' },
    { id: 'password', title: 'password' }
  ],
  append: true
});

// JWT secret
const JWT_SECRET = 'your-secret-key';

// Helper function to read users from CSV
const getUsers = () => {
  try {
    const content = fs.readFileSync(csvFilePath, 'utf-8');
    const lines = content.split('\n').slice(1); // Skip header
    return lines
      .filter(line => line.trim())
      .map(line => {
        const [email, password] = line.split(',');
        return { email, password };
      });
  } catch (error) {
    console.error('Error reading users:', error);
    return [];
  }
};

// Register endpoint
app.post('/api/register', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    // Check if user exists
    const users = getUsers();
    if (users.some(user => user.email === email)) {
      return res.status(400).json({ error: 'User already exists' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Save to CSV
    await csvWriter.writeRecords([
      { email, password: hashedPassword }
    ]);

    // Generate token
    const token = jwt.sign({ email }, JWT_SECRET, { expiresIn: '24h' });

    res.status(201).json({ token });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Registration failed' });
  }
});

// Login endpoint
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    // Find user
    const users = getUsers();
    const user = users.find(u => u.email === email);
    
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Verify password
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Generate token
    const token = jwt.sign({ email }, JWT_SECRET, { expiresIn: '24h' });

    res.json({ token });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});