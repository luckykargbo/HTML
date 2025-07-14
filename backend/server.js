// backend/server.js
// Node.js/Express backend with MySQL for full user auth (register, login, password reset)

const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const path = require('path');
const app = express();
const PORT = 3000;

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, '../public')));

// MySQL connection
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',         // your MySQL username
  password: 'password', // your MySQL password
  database: 'vnatk_market'
});

db.query(`
  CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) UNIQUE,
    username VARCHAR(255) UNIQUE,
    password VARCHAR(255),
    resetCode VARCHAR(10),
    resetCodeExpires BIGINT
  )
`);

// Health check route
app.get('/', (req, res) => {
  res.send('VNAT.K Market World backend is running.');
});

// Register endpoint
app.post('/api/register', async (req, res) => {
  let { username, email, password } = req.body;
  if (!username && email) username = email;
  if (!username || !email || !password) return res.status(400).json({ message: 'All fields required' });
  const hash = await bcrypt.hash(password, 10);
  db.query('INSERT INTO users (username, email, password) VALUES (?, ?, ?)', [username, email, hash], (err) => {
    if (err) return res.status(400).json({ message: 'User already exists' });
    res.json({ message: 'Registration successful' });
  });
});

// Login endpoint
app.post('/api/login', (req, res) => {
  const { email, username, password } = req.body;
  const userField = email ? 'email' : 'username';
  const userValue = email || username;
  if (!userValue || !password) return res.status(400).json({ message: 'Email/username and password required' });
  db.query(`SELECT * FROM users WHERE ${userField}=?`, [userValue], async (err, results) => {
    if (err || results.length === 0) return res.status(400).json({ message: 'Invalid credentials' });
    const user = results[0];
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ message: 'Invalid credentials' });
    res.json({ message: 'Login successful', username: user.username, email: user.email });
  });
});

// Send reset code endpoint
app.post('/api/send-reset-code', (req, res) => {
  const { email } = req.body;
  const code = Math.floor(100000 + Math.random() * 900000).toString();
  const expires = Date.now() + 15 * 60 * 1000;
  db.query(
    'UPDATE users SET resetCode=?, resetCodeExpires=? WHERE email=?',
    [code, expires, email],
    (err, result) => {
      if (err || result.affectedRows === 0) return res.status(404).json({ message: 'User not found' });
      // Send code via email here if needed
      res.json({ message: 'Reset code sent (demo: ' + code + ')' });
    }
  );
});

// Reset password endpoint
app.post('/api/reset-password', async (req, res) => {
  const { email, code, newPassword } = req.body;
  db.query(
    'SELECT * FROM users WHERE email=? AND resetCode=? AND resetCodeExpires > ?',
    [email, code, Date.now()],
    async (err, results) => {
      if (err || results.length === 0) return res.status(400).json({ message: 'Invalid or expired code' });
      const hash = await bcrypt.hash(newPassword, 10);
      db.query(
        'UPDATE users SET password=?, resetCode=NULL, resetCodeExpires=NULL WHERE email=?',
        [hash, email],
        (err2) => {
          if (err2) return res.status(500).json({ message: 'Database error' });
          res.json({ message: 'Password reset successful' });
        }
      );
    }
  );
});

// Listen only on localhost for Tor hidden service
app.listen(PORT, '127.0.0.1', () => console.log(`Backend running on http://127.0.0.1:${PORT}`));
