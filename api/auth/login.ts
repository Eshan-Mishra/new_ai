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

    // Read users from CSV
    const usersFile = join(process.cwd(), 'data', 'users.csv');
    let content: string;
    
    try {
      content = readFileSync(usersFile, 'utf-8');
    } catch (error) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const users = content
      .split('\n')
      .slice(1)
      .filter(line => line.trim())
      .map(line => {
        const [email, password] = line.split(',');
        return { email, password };
      });

    const user = users.find(u => u.email === email);
    
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign({ email }, JWT_SECRET, { expiresIn: '24h' });
    res.status(200).json({ token });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed. Please try again.' });
  }
}