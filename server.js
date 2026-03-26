const express = require("express");
const cors = require("cors");
require("dotenv").config();

const { Pool } = require("pg");
const jwt = require("jsonwebtoken");
const jwksRsa = require("jwks-rsa");

const app = express();
app.use(cors());
app.use(express.json());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false,
  },
});

const AUTH0_DOMAIN = "dev-iio7cnh3sn4jc7pd.us.auth0.com";

const client = jwksRsa({
  jwksUri: `https://${AUTH0_DOMAIN}/.well-known/jwks.json`,
});

function getKey(header, callback) {
  client.getSigningKey(header.kid, function (err, key) {
    const signingKey = key.getPublicKey();
    callback(null, signingKey);
  });
}

function verifyToken(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader) return res.status(401).send("No Authorization header");

  const token = authHeader.split(" ")[1];

  jwt.verify(token, getKey, {}, (err, decoded) => {
    if (err) return res.status(401).send("Invalid token");

    req.user = decoded;
    next();
  });
}

// Health
app.get("/", (req, res) => {
  res.send("ShareLoop API running");
});

// Sync user
app.post("/sync-user", verifyToken, async (req, res) => {
  const { sub, email, name } = req.user;

  await pool.query(
    `
    INSERT INTO users (auth0_id, email, name)
    VALUES ($1, $2, $3)
    ON CONFLICT (auth0_id) DO NOTHING
    `,
    [sub, email, name]
  );

  res.send("User synced");
});

// Create token
app.post("/create-token", verifyToken, async (req, res) => {
  const token = Math.random().toString(36).substring(2, 10);

  await pool.query(
    `INSERT INTO pairing_tokens (token, created_by)
     VALUES ($1, $2)`,
    [token, req.user.sub]
  );

  res.json({ token });
});

// Join loop
app.post("/join", verifyToken, async (req, res) => {
  const { token } = req.body;

  const tokenResult = await pool.query(
    `SELECT * FROM pairing_tokens WHERE token=$1 AND used=false`,
    [token]
  );

  if (tokenResult.rows.length === 0) {
    return res.status(400).send("Invalid token");
  }

  const creator = tokenResult.rows[0].created_by;

  const loop = await pool.query(
    `INSERT INTO loops DEFAULT VALUES RETURNING *`
  );

  const loopId = loop.rows[0].id;

  await pool.query(
    `INSERT INTO loop_members (loop_id, user_id)
     VALUES ($1, $2), ($1, $3)`,
    [loopId, creator, req.user.sub]
  );

  await pool.query(
    `UPDATE pairing_tokens SET used=true WHERE token=$1`,
    [token]
  );

  res.json({ loopId });
});

// 🔥 NEW — GET USER LOOPS
app.get("/my-loops", verifyToken, async (req, res) => {
  const userId = req.user.sub;

  const result = await pool.query(
    `
    SELECT DISTINCT loop_id
    FROM loop_members
    WHERE user_id = $1
    `,
    [userId]
  );

  res.json(result.rows);
});

app.listen(3000, () => {
  console.log("Server running on port 3000");
});