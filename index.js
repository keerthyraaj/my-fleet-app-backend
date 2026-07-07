// backend/index.js
const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const cors = require('cors');
require('dotenv').config();

const app = express();

const allowedOrigins = (process.env.CORS_ORIGIN || '')
  .split(',')
  .map((origin) => origin.trim())
  .filter(Boolean);

// Middleware
app.use(cors({
  origin: (origin, callback) => {
    if (!origin) {
      return callback(null, true);
    }

    if (allowedOrigins.length === 0 || allowedOrigins.includes(origin)) {
      return callback(null, true);
    }

    return callback(new Error('Not allowed by CORS'));
  },
  credentials: true
}));
app.use(express.json());

// Connect to Neon PostgreSQL using your connection string
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// LOGIN ENDPOINT
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: 'Email and password are required.' });
  }

  try {
    const userQuery = 'SELECT * FROM users WHERE email = $1';
    const result = await pool.query(userQuery, [email]);

    if (result.rows.length === 0) {
      return res.status(401).json({ message: 'Invalid email or password' });
    }

    const user = result.rows[0];

    let isPasswordValid = false;

    try {
      isPasswordValid = await bcrypt.compare(password, user.password_hash);
    } catch (error) {
      isPasswordValid = false;
    }

    if (!isPasswordValid && user.password_hash === password) {
      const hashedPassword = await bcrypt.hash(password, 10);
      await pool.query('UPDATE users SET password_hash = $1 WHERE user_id = $2', [hashedPassword, user.user_id]);
      isPasswordValid = true;
    }

    if (!isPasswordValid) {
      return res.status(401).json({ message: 'Invalid email or password' });
    }

    res.json({
      message: 'Login successful',
      fullName: user.full_name,
      email: user.email
    });
  } catch (error) {
    console.error('Database error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// DASHBOARD STATISTICS ENDPOINT
app.get('/api/dashboard/stats', async (req, res) => {
  const email = req.query.email;

  if (!email) {
    return res.status(400).json({ message: 'Email is required.' });
  }

  try {
    const userResult = await pool.query(
      'SELECT user_id, full_name FROM users WHERE email = $1',
      [email]
    );

    if (userResult.rows.length === 0) {
      return res.status(404).json({ message: 'User not found.' });
    }

    const user = userResult.rows[0];

    const statsQuery = `
      SELECT
        COUNT(uf.fleet_id) AS fleet_count,
        COALESCE(SUM(f.distance_covered_km), 0) AS total_distance_km,
        COALESCE(AVG(f.battery_life_percentage), 0) AS average_battery,
        COUNT(*) FILTER (WHERE f.current_status = 'idle') AS idle_fleets,
        COUNT(*) FILTER (WHERE f.current_status = 'active') AS active_fleets,
        COUNT(*) FILTER (WHERE f.current_status = 'charging') AS charging_fleets,
        COUNT(*) FILTER (WHERE f.current_status = 'maintenance') AS maintenance_fleets
      FROM user_fleets uf
      LEFT JOIN fleets f ON uf.fleet_id = f.fleet_id
      WHERE uf.user_id = $1
    `;

    const statsResult = await pool.query(statsQuery, [user.user_id]);

    const typeQuery = `
      SELECT f.vehicle_type AS type, COUNT(*) AS count
      FROM user_fleets uf
      LEFT JOIN fleets f ON uf.fleet_id = f.fleet_id
      WHERE uf.user_id = $1
      GROUP BY f.vehicle_type
      ORDER BY count DESC
    `;

    const typeResult = await pool.query(typeQuery, [user.user_id]);

    const stats = statsResult.rows[0];

    res.json({
      fullName: user.full_name,
      stats: {
        fleetCount: Number(stats.fleet_count || 0),
        totalDistanceKm: Number(stats.total_distance_km || 0),
        averageBattery: Number(stats.average_battery || 0),
        idleFleets: Number(stats.idle_fleets || 0),
        activeFleets: Number(stats.active_fleets || 0),
        chargingFleets: Number(stats.charging_fleets || 0),
        maintenanceFleets: Number(stats.maintenance_fleets || 0)
      },
      fleetTypes: typeResult.rows.map((row) => ({
        type: row.type || 'unassigned',
        count: Number(row.count || 0)
      }))
    });
  } catch (error) {
    console.error('Dashboard error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
