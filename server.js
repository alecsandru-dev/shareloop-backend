const express = require("express");
const cors = require("cors");
require("dotenv").config();

const { Pool } = require("pg");
const jwt = require("jsonwebtoken");
const jwksRsa = require("jwks-rsa");

const app = express();
app.use(cors());
app.use(express.json());

/**
 * ============================
 * DB CONNECTION
 * ============================
 */
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false,
  },
});

/**
 * ============================
 * AUTH0 CONFIG
 * ============================
 */
const AUTH0_DOMAIN = "dev-iio7cnh3sn4jc7pd.us.auth0.com";

const client = jwksRsa({
  jwksUri: `https://${AUTH0_DOMAIN}/.well-known/jwks.json`,
});

function getKey(header, callback) {
  client.getSigningKey(header.kid, function (err, key) {
    if (err) {
      console.error("JWKS error:", err);
      callback(err);
      return;
    }
    const signingKey = key.getPublicKey();
    callback(null, signingKey);
  });
}

function verifyToken(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    return res.status(401).send("No Authorization header");
  }

  const token = authHeader.split(" ")[1];

  jwt.verify(token, getKey, {}, (err, decoded) => {
    if (err) {
      console.error("Token error:", err);
      return res.status(401).send("Invalid token");
    }

    req.user = decoded;
    next();
  });
}

/**
 * ============================
 * ROUTES
 * ============================
 */

// Health check
app.get("/", (req, res) => {
  res.send("ShareLoop API running");
});

// DB test
app.get("/test-db", async (req, res) => {
  try {
    const result = await pool.query("SELECT NOW()");
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).send("DB error");
  }
});

// Sync Auth0 user → DB
app.post("/sync-user", verifyToken, async (req, res) => {
  console.log("SYNC ENDPOINT HIT");
  console.log("USER FROM TOKEN:", req.user);

  const { sub, email, name } = req.user;

  try {
    await pool.query(
      `
      INSERT INTO users (auth0_id, email, name)
      VALUES ($1, $2, $3)
      ON CONFLICT (auth0_id) DO NOTHING
      `,
      [sub, email, name]
    );

    console.log("User synced:", sub);

    res.send("User synced");
  } catch (err) {
    console.error("Sync error:", err);
    res.status(500).send("Error syncing user");
  }
});

/**
 * ============================
 * CREATE PAIRING TOKEN
 * ============================
 */
app.post("/create-token", verifyToken, async (req, res) => {
  const token = Math.random().toString(36).substring(2, 10);

  try {
    await pool.query(
      `
      INSERT INTO pairing_tokens (token, created_by)
      VALUES ($1, $2)
      `,
      [token, req.user.sub]
    );

    console.log("Token created:", token);

    res.json({ token });
  } catch (err) {
    console.error("Token error:", err);
    res.status(500).send("Error creating token");
  }
});

/**
 * ============================
 * JOIN LOOP USING TOKEN
 * ============================
 */
app.post("/join", verifyToken, async (req, res) => {
  const { token } = req.body;

  try {
    const tokenResult = await pool.query(
      `
      SELECT * FROM pairing_tokens
      WHERE token = $1 AND used = false
      `,
      [token]
    );

    if (tokenResult.rows.length === 0) {
      return res.status(400).send("Invalid or used token");
    }

    const creator = tokenResult.rows[0].created_by;

    // Create loop
    const loopResult = await pool.query(
      `
      INSERT INTO loops DEFAULT VALUES
      RETURNING *
      `
    );

    const loopId = loopResult.rows[0].id;

    // Add both users
    await pool.query(
      `
      INSERT INTO loop_members (loop_id, user_id)
      VALUES ($1, $2), ($1, $3)
      `,
      [loopId, creator, req.user.sub]
    );

    // Mark token as used
    await pool.query(
      `
      UPDATE pairing_tokens
      SET used = true
      WHERE token = $1
      `,
      [token]
    );

    console.log("Loop created:", loopId);

    res.json({ loopId });
  } catch (err) {
    console.error("Join error:", err);
    res.status(500).send("Error joining loop");
  }
});

/**
 * ============================
 * START SERVER
 * ============================
 */
app.listen(3000, () => {
  console.log("Server running on port 3000");
});