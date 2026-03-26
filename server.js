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
const AUTH0_DOMAIN = "dev-iio7cnh3sn4jc7pd.us.auth0.com"; // <-- your domain

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
 * START SERVER
 * ============================
 */
app.listen(3000, () => {
  console.log("Server running on port 3000");
});