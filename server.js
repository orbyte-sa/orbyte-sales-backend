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
const PORT = process.env.PORT || 10000;

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

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use('/uploads', express.static('uploads'));

// Ensure uploads directory exists
if (!fs.existsSync('uploads')) {
    fs.mkdirSync('uploads', { recursive: true });
}

// Database configuration - Using IP address for better connectivity
const dbConfig = {
    host: process.env.DB_HOST || '193.203.168.132',
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    port: 3306,
    connectTimeout: 30000,
    ssl: false,
    timezone: '+00:00'
};

console.log('Database config:', {
    host: dbConfig.host,
    user: dbConfig.user,
    database: dbConfig.database,
    port: dbConfig.port
});

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
let connectionAttempts = 0;
const maxRetries = 5;

async function initDB() {
    try {
        connectionAttempts++;
        console.log(`Database connection attempt ${connectionAttempts}/${maxRetries}`);
        
        db = await mysql.createConnection(dbConfig);
        
        // Test connection
        await db.execute('SELECT 1 as test');
        console.log('✅ Connected to MySQL database successfully');
        
        // Test if tables exist
        const [tables] = await db.execute(`
            SELECT table_name FROM information_schema.tables 
            WHERE table_schema = ? AND table_name IN ('users', 'cold_calling_reports', 'telemarketing_reports')
        `, [dbConfig.database]);
        
        console.log('Available tables:', tables.map(t => t.table_name));
        
        if (tables.length === 3) {
            console.log('✅ All required tables found');
        } else {
            console.log('⚠️ Some tables may be missing');
        }
        
    } catch (error) {
        console.error(`❌ Database connection failed (attempt ${connectionAttempts}):`, error.message);
        
        if (connectionAttempts < maxRetries) {
            console.log(`Retrying in 5 seconds...`);
            setTimeout(initDB, 5000);
        } else {
            console.error('❌ Max database connection attempts reached');
        }
    }
}

// Health check endpoint
app.get('/api/health', async (req, res) => {
    const health = {
        status: 'OK',
        message: 'Orbyte Sales API is running',
        timestamp: new Date().toISOString(),
        environment: process.env.NODE_ENV || 'development',
        database: 'disconnected'
    };
    
    // Check database connection
    if (db) {
        try {
            await db.execute('SELECT 1 as test');
            health.database = 'connected';
        } catch (error) {
            health.database = 'error: ' + error.message;
        }
    }
    
    res.json(health);
});

// Root endpoint
app.get('/', (req, res) => {
    res.json({ 
        message: 'Orbyte Sales API Server',
        status: 'Running',
        version: '1.0.0',
        endpoints: {
            health: '/api/health',
            login: '/api/auth/login',
            reports: '/api/reports',
            users: '/api/users (admin only)'
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

// Database check middleware
const requireDB = (req, res, next) => {
    if (!db) {
        return res.status(503).json({ error: 'Database connection not available' });
    }
    next();
};

// Auth Routes
app.post('/api/auth/login', requireDB, async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password are required' });
        }

        console.log('Login attempt for:', email);

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

        console.log('✅ Login successful for:', email);

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
        res.status(500).json({ error: 'Login failed: ' + error.message });
    }
});

// User Management Routes (Admin only)
app.get('/api/users', authenticateToken, requireAdmin, requireDB, async (req, res) => {
    try {
        const [users] = await db.execute(
            'SELECT id, name, email, role, executive_type, status, created_at FROM users ORDER BY created_at DESC'
        );
        res.json(users);
    } catch (error) {
        console.error('Get users error:', error);
        res.status(500).json({ error: 'Failed to fetch users' });
    }
});

app.post('/api/users', authenticateToken, requireAdmin, requireDB, async (req, res) => {
    try {
        const { name, email, password, role, executive_type } = req.body;

        if (!name || !email || !password || !role) {
            return res.status(400).json({ error: 'All fields are required' });
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

app.put('/api/users/:id', authenticateToken, requireAdmin, requireDB, async (req, res) => {
    try {
        const { id } = req.params;
        const { name, email, role, executive_type, status, password } = req.body;

        let updateQuery = 'UPDATE users SET name = ?, email = ?, role = ?, executive_type = ?, status = ?';
        let params = [name, email, role, executive_type, status];

        if (password) {
            const hashedPassword = await bcrypt.hash(password, 10);
            updateQuery += ', password = ?';
            params.push(hashedPassword);
        }

        updateQuery += ' WHERE id = ?';
        params.push(id);

        await db.execute(updateQuery, params);

        res.json({ message: 'User updated successfully' });

    } catch (error) {
        console.error('Update user error:', error);
        res.status(500).json({ error: 'Failed to update user' });
    }
});

// Report Routes
app.post('/api/reports/cold-calling', authenticateToken, requireDB, upload.single('photo_proof'), async (req, res) => {
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

app.post('/api/reports/telemarketing', authenticateToken, requireDB, async (req, res) => {
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
app.get('/api/reports', authenticateToken, requireDB, async (req, res) => {
    try {
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
            LIMIT 100
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
            LIMIT 100
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

// Delete report (same day only for executives)
app.delete('/api/reports/:type/:id', authenticateToken, requireDB, async (req, res) => {
    try {
        const { type, id } = req.params;
        const table = type === 'cold_calling' ? 'cold_calling_reports' : 'telemarketing_reports';

        // Check if report exists and belongs to user (or user is admin)
        const [reports] = await db.execute(
            `SELECT * FROM ${table} WHERE id = ? ${req.user.role !== 'admin' ? 'AND user_id = ?' : ''}`,
            req.user.role !== 'admin' ? [id, req.user.id] : [id]
        );

        if (reports.length === 0) {
            return res.status(404).json({ error: 'Report not found' });
        }

        const report = reports[0];

        // Check if report was created today (for non-admin users)
        if (req.user.role !== 'admin') {
            const today = new Date().toISOString().split('T')[0];
            const reportDate = new Date(report.created_at).toISOString().split('T')[0];
            
            if (today !== reportDate) {
                return res.status(403).json({ error: 'Can only delete reports from today' });
            }
        }

        // Delete photo file if exists
        if (type === 'cold_calling' && report.photo_proof) {
            const photoPath = path.join('uploads', report.photo_proof);
            if (fs.existsSync(photoPath)) {
                fs.unlinkSync(photoPath);
            }
        }

        await db.execute(`DELETE FROM ${table} WHERE id = ?`, [id]);

        res.json({ message: 'Report deleted successfully' });

    } catch (error) {
        console.error('Delete report error:', error);
        res.status(500).json({ error: 'Failed to delete report' });
    }
});

// Dashboard statistics
app.get('/api/dashboard/stats', authenticateToken, requireDB, async (req, res) => {
    try {
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

        // Get weekly activity
        const [weeklyActivity] = await db.execute(`
            SELECT 
                DATE(created_at) as date,
                COUNT(*) as count,
                'cold_calling' as type
            FROM cold_calling_reports 
            ${userCondition}
            ${userCondition ? 'AND' : 'WHERE'} created_at >= DATE_SUB(CURDATE(), INTERVAL 7 DAY)
            GROUP BY DATE(created_at)
            UNION ALL
            SELECT 
                DATE(created_at) as date,
                COUNT(*) as count,
                'telemarketing' as type
            FROM telemarketing_reports 
            ${userCondition}
            ${userCondition ? 'AND' : 'WHERE'} created_at >= DATE_SUB(CURDATE(), INTERVAL 7 DAY)
            GROUP BY DATE(created_at)
            ORDER BY date DESC
        `, [...userParam, ...userParam]);

        res.json({
            coldCalling: coldStats[0] || { total_visits: 0, deals_closed: 0, today_visits: 0 },
            telemarketing: teleStats[0] || { total_calls: 0, deals_closed: 0, today_calls: 0 },
            weeklyActivity
        });

    } catch (error) {
        console.error('Dashboard stats error:', error);
        res.status(500).json({ error: 'Failed to fetch dashboard statistics' });
    }
});

// Export reports as CSV (admin only)
app.get('/api/reports/export', authenticateToken, requireAdmin, requireDB, async (req, res) => {
    try {
        // Get all reports with user information
        const [allReports] = await db.execute(`
            SELECT 
                'Cold Calling' as report_type,
                u.name as executive_name,
                ccr.business_name,
                ccr.contact_person,
                ccr.contact_position,
                ccr.visit_time as activity_time,
                ccr.outcome,
                ccr.notes,
                ccr.created_at as submission_time,
                ccr.latitude,
                ccr.longitude,
                ccr.photo_proof
            FROM cold_calling_reports ccr
            JOIN users u ON ccr.user_id = u.id
            UNION ALL
            SELECT 
                'Telemarketing' as report_type,
                u.name as executive_name,
                tr.business_name,
                tr.contact_person,
                tr.contact_position,
                tr.call_time as activity_time,
                tr.outcome,
                tr.notes,
                tr.created_at as submission_time,
                NULL as latitude,
                NULL as longitude,
                NULL as photo_proof
            FROM telemarketing_reports tr
            JOIN users u ON tr.user_id = u.id
            ORDER BY submission_time DESC
        `);

        // Convert to CSV
        if (allReports.length === 0) {
            return res.status(404).json({ error: 'No reports found' });
        }

        const csvHeaders = [
            'Report Type', 'Executive Name', 'Business Name', 'Contact Person', 
            'Contact Position', 'Activity Time', 'Outcome', 'Notes', 
            'Submission Time', 'Latitude', 'Longitude', 'Photo Proof'
        ].join(',');

        const csvRows = allReports.map(row => [
            `"${row.report_type}"`,
            `"${row.executive_name}"`,
            `"${row.business_name}"`,
            `"${row.contact_person}"`,
            `"${row.contact_position}"`,
            `"${row.activity_time}"`,
            `"${row.outcome}"`,
            `"${row.notes || ''}"`,
            `"${row.submission_time}"`,
            `"${row.latitude || ''}"`,
            `"${row.longitude || ''}"`,
            `"${row.photo_proof || ''}"`
        ].join(',')).join('\n');

        const csv = csvHeaders + '\n' + csvRows;

        res.setHeader('Content-Type', 'text/csv');
        res.setHeader('Content-Disposition', `attachment; filename="orbyte_sales_reports_${new Date().toISOString().split('T')[0]}.csv"`);
        res.send(csv);

    } catch (error) {
        console.error('Export reports error:', error);
        res.status(500).json({ error: 'Failed to export reports' });
    }
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error('Error:', err);
    res.status(500).json({ error: 'Internal server error: ' + err.message });
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({ error: 'Endpoint not found' });
});

// Initialize database and start server
async function startServer() {
    console.log('🚀 Starting Orbyte Sales API Server...');
    console.log('Environment:', process.env.NODE_ENV || 'development');
    
    // Initialize database
    await initDB();
    
    // Start server
    app.listen(PORT, '0.0.0.0', () => {
        console.log(`✅ Server running on port ${PORT}`);
        console.log(`📡 Health check: http://localhost:${PORT}/api/health`);
        console.log(`🌐 API Base URL: http://localhost:${PORT}/api`);
    });
}

// Handle graceful shutdown
process.on('SIGTERM', async () => {
    console.log('SIGTERM received, shutting down gracefully');
    if (db) {
        await db.end();
    }
    process.exit(0);
});

process.on('SIGINT', async () => {
    console.log('SIGINT received, shutting down gracefully');
    if (db) {
        await db.end();
    }
    process.exit(0);
});

startServer().catch(console.error);
