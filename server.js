// server.js for Render.com deployment
const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 10000; // Render uses port 10000

// Middleware
app.use(cors({
    origin: [
        'http://localhost:3000',
        'https://team.orbyte360.com',           // Your actual subdomain
        'https://orbyte360.com',                // Your main domain
        'https://www.orbyte360.com',            // WWW version
        'https://orbyte-sales-api.onrender.com' // Backend URL
    ],
    credentials: true
}));
app.use(express.json());
app.use('/uploads', express.static('uploads'));

// Ensure uploads directory exists
if (!fs.existsSync('uploads')) {
    fs.mkdirSync('uploads');
}

// Database configuration for Render + Hostinger
const dbConfig = {
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    ssl: process.env.DB_SSL === 'true' ? { rejectUnauthorized: false } : false,
    connectTimeout: 60000,
    acquireTimeout: 60000,
    timeout: 60000,
    reconnect: true
};

// File upload configuration
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'uploads/')
    },
    filename: function (req, file, cb) {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
    }
});

const upload = multer({ 
    storage: storage,
    fileFilter: function (req, file, cb) {
        if (file.mimetype.startsWith('image/')) {
            cb(null, true);
        } else {
            cb(new Error('Only image files are allowed!'), false);
        }
    },
    limits: {
        fileSize: 5 * 1024 * 1024 // 5MB limit
    }
});

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'orbyte_sales_secret_key_2025';

// Database connection
let db;
async function initDB() {
    try {
        db = await mysql.createConnection(dbConfig);
        console.log('Connected to MySQL database');
        
        // Test connection
        await db.execute('SELECT 1');
        console.log('Database connection test successful');
    } catch (error) {
        console.error('Database connection failed:', error);
        // Don't exit in production, retry instead
        setTimeout(initDB, 5000);
    }
}

// Health check endpoint
app.get('/api/health', (req, res) => {
    res.json({ 
        status: 'OK', 
        message: 'Orbyte Sales API is running',
        timestamp: new Date().toISOString(),
        environment: process.env.NODE_ENV || 'development'
    });
});

// Root endpoint
app.get('/', (req, res) => {
    res.json({ 
        message: 'Orbyte Sales API Server',
        status: 'Running',
        endpoints: {
            health: '/api/health',
            login: '/api/auth/login',
            reports: '/api/reports'
        }
    });
});

// Authentication middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Access token required' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid or expired token' });
        }
        req.user = user;
        next();
    });
};

// Admin middleware
const requireAdmin = (req, res, next) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Admin access required' });
    }
    next();
};

// Auth Routes
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password are required' });
        }

        if (!db) {
            return res.status(500).json({ error: 'Database connection not available' });
        }

        const [users] = await db.execute(
            'SELECT * FROM users WHERE email = ? AND status = "active"',
            [email]
        );

        if (users.length === 0) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const user = users[0];
        const isValidPassword = await bcrypt.compare(password, user.password);

        if (!isValidPassword) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const token = jwt.sign(
            { 
                id: user.id, 
                email: user.email, 
                role: user.role,
                name: user.name,
                executive_type: user.executive_type
            },
            JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.json({
            token,
            user: {
                id: user.id,
                name: user.name,
                email: user.email,
                role: user.role,
                executive_type: user.executive_type
            }
        });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Login failed' });
    }
});

// User Management Routes (Admin only)
app.get('/api/users', authenticateToken, requireAdmin, async (req, res) => {
    try {
        if (!db) {
            return res.status(500).json({ error: 'Database connection not available' });
        }

        const [users] = await db.execute(
            'SELECT id, name, email, role, executive_type, status, created_at FROM users ORDER BY created_at DESC'
        );
        res.json(users);
    } catch (error) {
        console.error('Get users error:', error);
        res.status(500).json({ error: 'Failed to fetch users' });
    }
});

app.post('/api/users', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { name, email, password, role, executive_type } = req.body;

        if (!name || !email || !password || !role) {
            return res.status(400).json({ error: 'All fields are required' });
        }

        if (!db) {
            return res.status(500).json({ error: 'Database connection not available' });
        }

        // Check if user already exists
        const [existingUsers] = await db.execute(
            'SELECT id FROM users WHERE email = ?',
            [email]
        );

        if (existingUsers.length > 0) {
            return res.status(400).json({ error: 'User with this email already exists' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const [result] = await db.execute(
            'INSERT INTO users (name, email, password, role, executive_type, status) VALUES (?, ?, ?, ?, ?, "active")',
            [name, email, hashedPassword, role, executive_type]
        );

        res.json({ 
            id: result.insertId, 
            message: 'User created successfully' 
        });

    } catch (error) {
        console.error('Create user error:', error);
        res.status(500).json({ error: 'Failed to create user' });
    }
});

// Report Routes
app.post('/api/reports/cold-calling', authenticateToken, upload.single('photo_proof'), async (req, res) => {
    try {
        const {
            business_name,
            contact_person,
            contact_position,
            visit_time,
            outcome,
            notes,
            latitude,
            longitude
        } = req.body;

        if (!business_name || !contact_person || !contact_position || !visit_time || !outcome) {
            return res.status(400).json({ error: 'All required fields must be filled' });
        }

        if (!db) {
            return res.status(500).json({ error: 'Database connection not available' });
        }

        const photo_path = req.file ? req.file.filename : null;

        const [result] = await db.execute(`
            INSERT INTO cold_calling_reports 
            (user_id, business_name, contact_person, contact_position, visit_time, photo_proof, outcome, notes, latitude, longitude, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())
        `, [req.user.id, business_name, contact_person, contact_position, visit_time, photo_path, outcome, notes, latitude, longitude]);

        res.json({ 
            id: result.insertId, 
            message: 'Cold calling report submitted successfully' 
        });

    } catch (error) {
        console.error('Submit cold calling report error:', error);
        res.status(500).json({ error: 'Failed to submit report' });
    }
});

app.post('/api/reports/telemarketing', authenticateToken, async (req, res) => {
    try {
        const {
            business_name,
            contact_person,
            contact_position,
            call_time,
            outcome,
            notes
        } = req.body;

        if (!business_name || !contact_person || !contact_position || !call_time || !outcome) {
            return res.status(400).json({ error: 'All required fields must be filled' });
        }

        if (!db) {
            return res.status(500).json({ error: 'Database connection not available' });
        }

        const [result] = await db.execute(`
            INSERT INTO telemarketing_reports 
            (user_id, business_name, contact_person, contact_position, call_time, outcome, notes, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, NOW())
        `, [req.user.id, business_name, contact_person, contact_position, call_time, outcome, notes]);

        res.json({ 
            id: result.insertId, 
            message: 'Telemarketing report submitted successfully' 
        });

    } catch (error) {
        console.error('Submit telemarketing report error:', error);
        res.status(500).json({ error: 'Failed to submit report' });
    }
});

// Get reports (filtered by user role)
app.get('/api/reports', authenticateToken, async (req, res) => {
    try {
        if (!db) {
            return res.status(500).json({ error: 'Database connection not available' });
        }

        const { date_from, date_to, outcome, business_name } = req.query;
        let conditions = [];
        let params = [];

        // If not admin, only show user's own reports
        if (req.user.role !== 'admin') {
            conditions.push('user_id = ?');
            params.push(req.user.id);
        }

        if (date_from) {
            conditions.push('DATE(created_at) >= ?');
            params.push(date_from);
        }
        if (date_to) {
            conditions.push('DATE(created_at) <= ?');
            params.push(date_to);
        }
        if (outcome) {
            conditions.push('outcome = ?');
            params.push(outcome);
        }
        if (business_name) {
            conditions.push('business_name LIKE ?');
            params.push(`%${business_name}%`);
        }

        const whereClause = conditions.length > 0 ? 'WHERE ' + conditions.join(' AND ') : '';

        // Get cold calling reports
        const [coldReports] = await db.execute(`
            SELECT 
                ccr.*,
                u.name as user_name,
                'cold_calling' as report_type
            FROM cold_calling_reports ccr
            JOIN users u ON ccr.user_id = u.id
            ${whereClause}
            ORDER BY ccr.created_at DESC
        `, params);

        // Get telemarketing reports
        const [teleReports] = await db.execute(`
            SELECT 
                tr.*,
                u.name as user_name,
                'telemarketing' as report_type,
                call_time as visit_time,
                NULL as photo_proof,
                NULL as latitude,
                NULL as longitude
            FROM telemarketing_reports tr
            JOIN users u ON tr.user_id = u.id
            ${whereClause}
            ORDER BY tr.created_at DESC
        `, params);

        // Combine and sort reports
        const allReports = [...coldReports, ...teleReports].sort(
            (a, b) => new Date(b.created_at) - new Date(a.created_at)
        );

        res.json(allReports);

    } catch (error) {
        console.error('Get reports error:', error);
        res.status(500).json({ error: 'Failed to fetch reports' });
    }
});

// Dashboard statistics
app.get('/api/dashboard/stats', authenticateToken, async (req, res) => {
    try {
        if (!db) {
            return res.status(500).json({ error: 'Database connection not available' });
        }

        const userCondition = req.user.role !== 'admin' ? 'WHERE user_id = ?' : '';
        const userParam = req.user.role !== 'admin' ? [req.user.id] : [];

        // Get cold calling stats
        const [coldStats] = await db.execute(`
            SELECT 
                COUNT(*) as total_visits,
                SUM(CASE WHEN outcome = 'Deal Closed' THEN 1 ELSE 0 END) as deals_closed,
                SUM(CASE WHEN DATE(created_at) = CURDATE() THEN 1 ELSE 0 END) as today_visits
            FROM cold_calling_reports 
            ${userCondition}
        `, userParam);

        // Get telemarketing stats  
        const [teleStats] = await db.execute(`
            SELECT 
                COUNT(*) as total_calls,
                SUM(CASE WHEN outcome = 'Deal Closed' THEN 1 ELSE 0 END) as deals_closed,
                SUM(CASE WHEN DATE(created_at) = CURDATE() THEN 1 ELSE 0 END) as today_calls
            FROM telemarketing_reports 
            ${userCondition}
        `, userParam);

        res.json({
            coldCalling: coldStats[0] || { total_visits: 0, deals_closed: 0, today_visits: 0 },
            telemarketing: teleStats[0] || { total_calls: 0, deals_closed: 0, today_calls: 0 },
            weeklyActivity: [] // Simplified for now
        });

    } catch (error) {
        console.error('Dashboard stats error:', error);
        res.status(500).json({ error: 'Failed to fetch dashboard statistics' });
    }
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error('Error:', err);
    res.status(500).json({ error: 'Internal server error' });
});

// Start server
async function startServer() {
    await initDB();
    
    app.listen(PORT, '0.0.0.0', () => {
        console.log(`Server running on port ${PORT}`);
        console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
    });
}

startServer().catch(console.error);
