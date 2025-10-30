// at top keep imports
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const pool = require("../config/db");
const generateUID = require("../utils/generateUID");
const sendOTP = require("../utils/sendOTP");

exports.register = async (req, res) => {
  const { username, email, password, role } = req.body;

  try {
    const userCheck = await pool.query("SELECT * FROM users WHERE email=$1", [email]);
    if (userCheck.rows.length > 0) return res.status(400).json({ message: "User exists" });

    const hashed = await bcrypt.hash(password, 10);

    // Lookup role in DB defensively
    const roleRes = await pool.query("SELECT id, role_name FROM roles WHERE UPPER(role_name) = $1", [role?.toString().toUpperCase()]);
    const roleId = roleRes.rows[0]?.id ?? null;

    if (!roleId) {
      console.warn("⚠️ Role not found, defaulting to USER if available");
      const fallback = await pool.query("SELECT id FROM roles WHERE UPPER(role_name)='USER' LIMIT 1");
      if (fallback.rows[0]) {
        roleId = fallback.rows[0].id;
      }
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

    const userRes = await pool.query(
      `INSERT INTO users (username, email, password, role_id, otp_code, otp_expires_at)
       VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, username, email`,
      [username, email, hashed, roleId, otp, expiresAt]
    );

    const userId = userRes.rows[0].id;
    const u_id = generateUID("USR", userId);
    await pool.query("UPDATE users SET u_id=$1 WHERE id=$2", [u_id, userId]);

    // send OTP and if send fails, delete the created user (optional) or return error
    try {
      await sendOTP(email, otp);
    } catch (mailErr) {
      // optional: clean up user if email couldn't be sent
      await pool.query("DELETE FROM users WHERE id=$1", [userId]);
      return res.status(500).json({ message: "Failed to send OTP. Check email config.", error: mailErr.message });
    }

    return res.status(201).json({ message: "OTP sent. Verify your email.", email });
  } catch (err) {
    console.error("Register Error:", err);
    res.status(500).json({ error: err.message });
  }
};

exports.verifyOTP = async (req, res) => {
  const { email, otp } = req.body;
  try {
    const result = await pool.query("SELECT u.*, r.role_name FROM users u LEFT JOIN roles r ON u.role_id = r.id WHERE u.email=$1", [email]);
    if (result.rows.length === 0) return res.status(404).json({ message: "User not found" });

    const user = result.rows[0];
    // ensure otp_expires_at is a Date object before comparing
    const now = new Date();
    const expiresAt = user.otp_expires_at ? new Date(user.otp_expires_at) : null;

    if (!user.otp_code || user.otp_code !== otp || !expiresAt || now > expiresAt)
      return res.status(400).json({ message: "Invalid or expired OTP" });

    // mark verified and clear otp fields
    await pool.query("UPDATE users SET verified=true, otp_code=NULL, otp_expires_at=NULL WHERE email=$1", [email]);

    // create token and return user data (frontend expects token + user)
    const token = jwt.sign(
      { id: user.id, role: user.role_name },
      process.env.JWT_SECRET,
      { expiresIn: "1d" }
    );

    // optional: store token in tokens table
    await pool.query(
      "INSERT INTO tokens (user_id, token, token_type, expires_at) VALUES ($1, $2, $3, NOW() + INTERVAL '1 day')",
      [user.id, token, "ACCESS"]
    );

    const safeUser = {
      id: user.id,
      u_id: user.u_id,
      username: user.username,
      email: user.email,
      role_name: user.role_name,
      verified: true,
    };

    return res.json({ message: "Email verified successfully!", token, user: safeUser });
  } catch (err) {
    console.error("verifyOTP Error:", err);
    res.status(500).json({ error: err.message });
  }
};


