import { VercelRequest, VercelResponse } from '@vercel/node';
import { readFileSync } from 'fs';
import { join } from 'path';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

// Load registration codes
const registrationCodes = new Set(
  readFileSync(join(process.cwd(), 'data', 'registration-codes.txt'), 'utf-8')
    .split('\n')
    .map(code => code.trim())
    .filter(Boolean)
);

export default async function handler(req: VercelRequest, res: VercelResponse) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const { email, password, registrationCode } = req.body;

    if (!email || !password || !registrationCode) {
      return res.status(400).json({ error: 'Email, password, and registration code are required' });
    }

    // Verify registration code
    if (!registrationCodes.has(registrationCode)) {
      return res.status(400).json({ error: 'Invalid registration code' });
    }

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ error: 'Invalid email format' });
    }

    // Validate password strength
    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters long' });
    }

    // Read existing users
    const usersFile = join(process.cwd(), 'data', 'users.csv');
    let content: string;
    
    try {
      content = readFileSync(usersFile, 'utf-8');
    } catch (error) {
      content = 'email,password,registrationCode\n';
    }

    const users = content
      .split('\n')
      .slice(1)
      .filter(line => line.trim())
      .map(line => {
        const [email] = line.split(',');
        return email;
      });

    if (users.includes(email)) {
      return res.status(400).json({ error: 'User already exists' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Generate JWT token
    const token = jwt.sign({ email }, JWT_SECRET, { expiresIn: '24h' });
    
    res.status(201).json({ token });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Registration failed. Please try again.' });
  }
}