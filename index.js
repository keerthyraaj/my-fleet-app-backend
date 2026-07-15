// backend/index.js
const express = require('express');
const session = require('express-session');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const cors = require('cors');
require('dotenv').config();

const app = express();
app.set('trust proxy', 1);

const configuredOrigins = (process.env.CORS_ORIGIN || '')
  .split(',')
  .map((origin) => origin.trim())
  .filter(Boolean);

const defaultAllowedOrigins = [
  'http://localhost:3000',
  'http://localhost:5173',
  'http://127.0.0.1:3000',
  'http://127.0.0.1:5173'
];

const isAllowedOrigin = (origin) => {
  if (!origin) {
    return true;
  }

  const normalizedOrigin = origin.replace(/\/$/, '');
  const knownOrigins = [...configuredOrigins, ...defaultAllowedOrigins];

  return knownOrigins.includes(normalizedOrigin);
};

// Middleware
app.use(cors({
  origin: (origin, callback) => {
    if (isAllowedOrigin(origin)) {
      return callback(null, origin || true);
    }

    return callback(new Error('Not allowed by CORS'));
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.options('*', cors({
  origin: (origin, callback) => {
    if (isAllowedOrigin(origin)) {
      return callback(null, origin || true);
    }

    return callback(new Error('Not allowed by CORS'));
  },
  credentials: true
}));
app.use(express.json());
app.use(session({
  secret: process.env.SESSION_SECRET || 'fleet-session-secret',

  resave: false,

  saveUninitialized: false,

  proxy: true,

  cookie: {
    httpOnly: true,

    sameSite: 'none',

    secure: process.env.NODE_ENV === 'production',

    maxAge: 1000 * 60 * 60 * 24 // 24 Hours
  }
}));

// Connect to Neon PostgreSQL using your connection string
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

const requireAuth = (req, res, next) => {
  if (!req.session?.user) {
    return res.status(401).json({ message: 'Not authenticated' });
  }

  next();
};

// ADD THIS ADMIN SECURITY MIDDLEWARE
const requireAdmin = (req, res, next) => {
  if (!req.session?.user || req.session.user.role !== 'admin') {
    return res.status(403).json({ message: 'Forbidden: Admin access required' });
  }
  next();
};

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

    req.session.user = {
      userId: user.user_id,
      fullName: user.full_name,
      email: user.email,
      role: user.role
    };

    res.json({
      message: 'Login successful',
      fullName: user.full_name,
      email: user.email,
      role: user.role
    });
  } catch (error) {
    console.error('Database error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// ======================================================
// RESTORE USER SESSION AFTER PAGE REFRESH
// ======================================================
app.get('/api/auth/me', (req, res) => {

    if (!req.session || !req.session.user) {
        return res.status(401).json({
            message: "Not authenticated"
        });
    }

    return res.json({
        fullName: req.session.user.fullName,
        email: req.session.user.email,
        role: req.session.user.role
    });

});


// DASHBOARD STATISTICS ENDPOINT
app.get('/api/dashboard/stats', requireAuth, async (req, res) => {
  try {
    const user = req.session.user;

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

    const statsResult = await pool.query(statsQuery, [user.userId]);

    const typeQuery = `
      SELECT f.vehicle_type AS type, COUNT(*) AS count
      FROM user_fleets uf
      LEFT JOIN fleets f ON uf.fleet_id = f.fleet_id
      WHERE uf.user_id = $1
      GROUP BY f.vehicle_type
      ORDER BY count DESC
    `;

    const typeResult = await pool.query(typeQuery, [user.userId]);

    const stats = statsResult.rows[0];

    res.json({
      fullName: user.fullName,
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
app.get('/api/fleet_schedule_demo/:fleetId', requireAuth, async (req, res) => {
  try {
    const { fleetId } = req.params;
    const userId = req.session.user.userId;

    const query = `
      SELECT
        fs.schedule_id,
        fs.fleet_id,
        fs.start_lat,
        fs.start_long,
        fs.end_lat,
        fs.end_long,
        fs.start_time,
        fs.end_time,
        fs.speed_kmh
      FROM fleet_schedules fs
      JOIN user_fleets uf
        ON uf.fleet_id = fs.fleet_id
      WHERE uf.user_id = $1
        AND fs.fleet_id = $2
      ORDER BY fs.start_time DESC
      LIMIT 1
    `;

    const result = await pool.query(query, [userId, fleetId]);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'No schedule found for this fleet.' });
    }

    return res.status(200).json({ schedule: result.rows[0] });
  } catch (error) {
    console.error('Fleet schedule demo error:', error);
    return res.status(500).json({ message: 'Failed to load schedule demo data.' });
  }
});

app.get('/api/auth/me', requireAuth, (req, res) => {
  res.json({ user: req.session.user });
});

app.post('/api/logout', (req, res) => {
  req.session.destroy((error) => {
    if (error) {
      return res.status(500).json({ message: 'Failed to logout' });
    }

    res.clearCookie('connect.sid');
    return res.json({ message: 'Logged out successfully' });
  });
});

//Fleets position endpoint
app.get('/api/fleets', requireAuth, async (req, res) => {
  try {
    const user = req.session.user;

    const query = `
      SELECT
        f.fleet_id,
        f.vehicle_type,
        f.battery_life_percentage,
        f.distance_covered_km,
        f.current_status,
        f.last_ping_at,
        fp.lat,
        fp.long,
        fp.current_ts

      FROM users u

      JOIN user_fleets uf
        ON uf.user_id = u.user_id

      JOIN fleets f
        ON f.fleet_id = uf.fleet_id

      LEFT JOIN LATERAL (
        SELECT
          lat,
          long,
          current_ts
        FROM fleet_position
        WHERE fleet_id = f.fleet_id
        ORDER BY current_ts DESC
        LIMIT 1
      ) fp ON TRUE

      WHERE u.user_id = $1

      ORDER BY f.vehicle_type;
    `;

    const result = await pool.query(query, [user.userId]);

    return res.status(200).json({
      fleets: result.rows,
    });
  } catch (error) {
    console.error("Fleet map error:", error);

    return res.status(500).json({
      error: "Failed to fetch fleet positions",
    });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));


// ==========================================
// ADMIN USER MANAGEMENT ENDPOINTS (CRUD)
// ==========================================

// 1. READ: Get all users (Managers & Operators)
app.get('/api/admin/users', requireAuth, requireAdmin, async (req, res) => {
  try {
    const result = await pool.query('SELECT user_id, full_name, email, role, is_active FROM users ORDER BY created_at DESC');
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ message: 'Failed to fetch users' });
  }
});

// 2. CREATE: Add new manager/operator
app.post('/api/admin/users', requireAuth, requireAdmin, async (req, res) => {
  const { full_name, email, password, role } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (full_name, email, password_hash, role) VALUES ($1, $2, $3, $4) RETURNING user_id, full_name, email, role',
      [full_name, email, hashedPassword, role]
    );
    res.status(201).json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ message: 'Failed to create user. Email may already exist.' });
  }
});

// 3. UPDATE: Modify user roles or names
app.put('/api/admin/users/:id', requireAuth, requireAdmin, async (req, res) => {
  const { full_name, email, role, is_active } = req.body;
  try {
    await pool.query(
      'UPDATE users SET full_name = $1, email = $2, role = $3, is_active = $4, updated_at = CURRENT_TIMESTAMP WHERE user_id = $5',
      [full_name, email, role, is_active, req.params.id]
    );
    res.json({ message: 'User updated successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Failed to update user' });
  }
});

// 4. DELETE: Filter out self-deletion to prevent locked out administrators
app.delete('/api/admin/users/:id', requireAuth, requireAdmin, async (req, res) => {
  try {
    if (req.params.id === req.session.user.userId) {
      return res.status(400).json({ message: 'Security action denied: You cannot delete your own active admin profile.' });
    }
    await pool.query('DELETE FROM users WHERE user_id = $1', [req.params.id]);
    res.json({ message: 'User deleted successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Failed to delete user' });
  }
});

// ==========================================
// ADMIN FLEET MANAGEMENT ENDPOINTS (CRUD)
// ==========================================

// 1. CREATE: Deploy a new vehicle asset
app.post('/api/admin/fleets', requireAuth, requireAdmin, async (req, res) => {
  const { vehicle_type, battery_life_percentage, current_status } = req.body;
  try {
    const result = await pool.query(
      'INSERT INTO fleets (vehicle_type, battery_life_percentage, current_status) VALUES ($1, $2, $3) RETURNING *',
      [vehicle_type, battery_life_percentage, current_status || 'idle']
    );
    res.status(201).json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ message: 'Failed to add fleet asset' });
  }
});

// 2. UPDATE: Edit full fleet configuration values
app.put('/api/admin/fleets/:id', requireAuth, requireAdmin, async (req, res) => {
  const { vehicle_type, battery_life_percentage, distance_covered_km, current_status } = req.body;
  try {
    await pool.query(
      'UPDATE fleets SET vehicle_type = $1, battery_life_percentage = $2, distance_covered_km = $3, current_status = $4 WHERE fleet_id = $5',
      [vehicle_type, battery_life_percentage, distance_covered_km, current_status, req.params.id]
    );
    res.json({ message: 'Fleet updated successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Failed to update fleet asset' });
  }
});

// 3. DELETE: Decommission a fleet asset
app.delete('/api/admin/fleets/:id', requireAuth, requireAdmin, async (req, res) => {
  try {
    await pool.query('DELETE FROM fleets WHERE fleet_id = $1', [req.params.id]);
    res.json({ message: 'Fleet asset removed successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Failed to delete fleet asset' });
  }
});
