const express = require('express')
const path = require('path')
const bodyParser = require('body-parser')
const sqlite3 = require('sqlite3').verbose()
const bcrypt = require('bcrypt')

const app = express()

// Parse incoming form data
app.use(bodyParser.urlencoded({ extended: true }))

// Serve all static files (html, css, js)
app.use(express.static(path.join(__dirname, '.')))

// Database setup
const db = new sqlite3.Database('./database.db', (err) => {
  if (err) console.error(err.message)
  else console.log('✅ Connected to database')
})

db.run(`CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT,
  email TEXT UNIQUE,
  password TEXT
)`)

// Signup route
app.post('/signup', async (req, res) => {
  const { username, email, password } = req.body
  try {
    const hashedPassword = await bcrypt.hash(password, 10)
    const query = `INSERT INTO users(username, email, password) VALUES(?,?,?)`
    db.run(query, [username, email, hashedPassword], (err) => {
      if (err) return res.status(400).send('Error signing up')
      res.redirect('/dashboard.html')
    })
  } catch (error) {
    res.status(500).send('Error hashing password')
  }
})

// Login route
app.post('/login', (req, res) => {
  const { email, password } = req.body
  const query = `SELECT * FROM users WHERE email=?`
  db.get(query, [email], async (err, user) => {
    if (err) return res.status(500).send('Server error')
    if (!user) return res.status(401).send('❌ Invalid login')
    const isMatch = await bcrypt.compare(password, user.password)
    if (isMatch) res.redirect('/dashboard.html')
    else res.status(401).send('❌ Invalid login')
  })
})

app.listen(3000, () => {
  console.log('Server listening at http://localhost:3000')
})
