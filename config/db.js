const { Pool } = require("pg");
require("dotenv").config();

const isProduction = process.env.NODE_ENV === "production";

const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT || 5432,
  max: 20, // max number of clients in the pool
  idleTimeoutMillis: 30000, // close idle clients after 30s
  connectionTimeoutMillis: 2000, // return error after 2s if cannot connect
  ssl: isProduction
    ? { require: true, rejectUnauthorized: false } // ✅ Required by Render
    : false, // ❌ Disable SSL locally
});

pool.on("connect", () => {
  console.log("✅ Connected to PostgreSQL");
});

pool.on("error", (err) => {
  console.error("❌ Unexpected database error:", err.message);
  // Optional reconnect logic
  setTimeout(() => {
    console.log("♻️ Reconnecting to database...");
  }, 2000);
});

// Test connection once on startup
pool.query("SELECT NOW()")
  .then((res) => console.log("🕐 DB time:", res.rows[0].now))
  .catch((err) => console.error("❌ PostgreSQL connection error:", err));

module.exports = pool;
