const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const mysql = require('mysql');

const app = express();

// Middleware to parse JSON in requests
app.use(express.json());

// Database configuration
const dbConfig = {
  host: 'localhost',
  user: 'root',
  password: 'password',
  database: 'mydatabase'
};

// Connection pool for MySQL
const pool = mysql.createPool(dbConfig);

// JWT secret key
const secretKey = 'mysecretkey';

// Helper function to generate a JWT token
function generateToken(user) {
  return jwt.sign({ id: user.id, username: user.username }, secretKey);
}

// Helper function to validate a JWT token
function validateToken(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    res.status(401).json({ message: 'Authorization header is missing' });
    return;
  }
  const token = authHeader.split(' ')[1];
  try {
    const decodedToken = jwt.verify(token, secretKey);
    req.user = decodedToken;
    next();
  } catch (error) {
    res.status(401).json({ message: 'Invalid token' });
  }
}

// POST /login
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const conn = await pool.getConnection();
    const [rows] = await conn.execute('SELECT * FROM users WHERE username = ?', [username]);
    conn.release();
    if (rows.length === 0) {
      res.status(401).json({ message: 'Invalid credentials' });
      return;
    }
    const user = rows[0];
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      res.status(401).json({ message: 'Invalid credentials' });
      return;
    }
    const token = generateToken(user);
    res.json({ token });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// POST /register - create a new user in the "users" table
app.post('/register', (req, res) => {
    const username = req.body.username;
    const password = req.body.password;
  
    // insert a new user into the "users" table
    pool.query('INSERT INTO users (username, password) VALUES (?, ?)', [username, password], (error, results) => {
      if (error) {
        console.error(error);
        res.status(500).json({ error: 'Internal server error' });
        return;
      }
  
      res.json({ message: 'User created successfully' });
    });
  });
  
  // GET /posts - return a list of all posts with the username of the user who created each post
  app.get('/posts', (req, res) => {
    // join the "posts" and "users" tables to get the username of the user who created each post
    pool.query('SELECT posts.*, users.username FROM posts JOIN users ON posts.user_id = users.id', (error, results) => {
      if (error) {
        console.error(error);
        res.status(500).json({ error: 'Internal server error' });
        return;
      }
  
      res.json(results);
    });
  });
  
  // GET /posts/:userId - return a list of all posts by the specified user
  app.get('/posts/:userId', (req, res) => {
    const userId = req.params.userId;
  
    // get all posts by the specified user
    pool.query('SELECT * FROM posts WHERE user_id = ?', [userId], (error, results) => {
      if (error) {
        console.error(error);
        res.status(500).json({ error: 'Internal server error' });
        return;
      }
  
      res.json(results);
    });
  });

  app.post('/posts/new', (req, res) => {
    const post = req.body;
    if (!post.title || !post.content) {
      return res.status(400).json({ message: 'Please provide a title and content for your post.' });
    }
    const sql = 'INSERT INTO posts (title, content) VALUES (?, ?)';
    connection.query(sql, [post.title, post.content], (error, results, fields) => {
      if (error) {
        console.error(error);
        return res.status(500).json({ message: 'Failed to create a new post.' });
      }
      return res.status(201).json({ message: 'Post created successfully.' });
    });
  });
  
  const port = 3000;
  app.listen(port, () => {
    console.log(`Server running on port ${port}.`);
  });