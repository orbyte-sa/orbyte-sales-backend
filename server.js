// server.js (Updated & Corrected)

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
        'https://team.orbyte360.com',
        'https://orbyte360.com',
        'https://www.orbyte360.com',
        'https://orbyte-sales-api.onrender.com'
    ],
    credentials: true
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Ensure uploads directory exists
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir, { recursive: true });
}

// Database configuration
const poolConfig = {
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    port: 3306,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
};
const pool = mysql.createPool(poolConfig);

// File upload configuration (memory storage for CSV processing)
const storage = multer.memoryStorage();
const upload = multer({ storage: storage });

const JWT_SECRET = process.env.JWT_SECRET;

// --- MIDDLEWARE ---
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Access token required' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Invalid or expired token' });
        req.user = user;
        next();
    });
};
const requireAdmin = (req, res, next) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Admin access required' });
    }
    next();
};

// --- AUTH ROUTES ---
app.post('/api/auth/login', async (req, res) => {
    let connection;
    try {
        const { email, password } = req.body;
        connection = await pool.getConnection();
        const [users] = await connection.execute('SELECT * FROM users WHERE email = ? AND status = "active"', [email]);

        if (users.length === 0) return res.status(401).json({ error: 'Invalid credentials' });
        
        const user = users[0];
        const isValidPassword = await bcrypt.compare(password, user.password);
        if (!isValidPassword) return res.status(401).json({ error: 'Invalid credentials' });

        await connection.execute('UPDATE users SET last_login = NOW() WHERE id = ?', [user.id]);

        const token = jwt.sign({ id: user.id, email: user.email, role: user.role, name: user.name }, JWT_SECRET, { expiresIn: '24h' });
        res.json({ token, user: { id: user.id, name: user.name, email: user.email, role: user.role } });
    } catch (error) {
        res.status(500).json({ error: 'Login failed' });
    } finally {
        if (connection) connection.release();
    }
});

// --- USER ROUTES ---
app.get('/api/users', authenticateToken, requireAdmin, async (req, res) => {
    let connection;
    try {
        connection = await pool.getConnection();
        const [users] = await connection.execute('SELECT id, name, email, role, status, department FROM users ORDER BY name ASC');
        res.json(users);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch users' });
    } finally {
        if (connection) connection.release();
    }
});


// --- BUSINESS ROUTES ---
app.get('/api/businesses', authenticateToken, async (req, res) => {
    let connection;
    try {
        connection = await pool.getConnection();
        // FIX: Correctly filter out archived businesses
        const [businesses] = await connection.execute("SELECT * FROM businesses WHERE status != 'Archived' ORDER BY created_at DESC");
        res.json(businesses);
    } catch (error) {
        console.error('Get businesses error:', error);
        res.status(500).json({ error: 'Failed to fetch businesses' });
    } finally {
        if (connection) connection.release();
    }
});

// FIX: Changed to soft delete by setting status to 'Archived'
app.delete('/api/businesses/:id', authenticateToken, requireAdmin, async (req, res) => {
    let connection;
    try {
        const { id } = req.params;
        connection = await pool.getConnection();
        await connection.execute("UPDATE businesses SET status = 'Archived' WHERE id = ?", [id]);
        res.json({ message: 'Business archived successfully' });
    } catch (error) {
        res.status(500).json({ error: 'Failed to archive business' });
    } finally {
        if (connection) connection.release();
    }
});

app.post('/api/businesses/upload', authenticateToken, requireAdmin, upload.single('business_csv'), async (req, res) => {
    if (!req.file) return res.status(400).json({ error: 'No file uploaded.' });
    
    let connection;
    try {
        const businesses = [];
        const buffer = req.file.buffer.toString('utf-8');
        const rows = buffer.split('\n').slice(1); // Skip header

        for (const row of rows) {
            if (!row) continue;
            // Expects: business_name,contact_person,phone,email,address
            const [business_name, contact_person, phone, email, address] = row.split(',').map(item => item.trim().replace(/"/g, ''));
            if (business_name) {
                businesses.push([business_name, contact_person || null, phone || null, email || null, address || null, req.user.id]);
            }
        }
        
        if (businesses.length === 0) return res.status(400).json({ error: 'CSV file is empty or invalid.' });

        connection = await pool.getConnection();
        await connection.query('INSERT INTO businesses (business_name, contact_person, phone, email, address, created_by) VALUES ?', [businesses]);
        res.status(201).json({ message: `${businesses.length} businesses uploaded successfully.` });

    } catch (error) {
        res.status(500).json({ error: 'Failed to process CSV file.' });
    } finally {
        if (connection) connection.release();
    }
});


// --- REPORT ROUTES ---
async function handleReportSubmission(connection, type, req) {
    const { business_name, contact_person, contact_position, outcome, notes, business_id } = req.body;
    const timeField = type === 'cold_calling' ? 'visit_time' : 'call_time';
    const activityTime = req.body[timeField];
    const photo_path = req.file ? `photo_proof-${Date.now()}${path.extname(req.file.originalname)}` : null;

    // FIX: Aligned outcome list with the database schema
    const validOutcomes = ['Deal Closed', 'Appointment Scheduled', 'Not Interested', 'Follow-up Needed', 'Other'];
    if (!business_name || !outcome || !validOutcomes.includes(outcome)) {
        throw new Error('Required fields are missing or outcome is invalid.');
    }

    if (photo_path) {
        fs.writeFileSync(path.join(uploadsDir, photo_path), req.file.buffer);
    }

    let effectiveBusinessId = business_id;
    if (!effectiveBusinessId || effectiveBusinessId === 'null') {
         const [newBusinessResult] = await connection.execute(
            'INSERT INTO businesses (business_name, contact_person, contact_position, created_by, assigned_to, status) VALUES (?, ?, ?, ?, ?, ?)',
            [business_name, contact_person, contact_position, req.user.id, req.user.id, 'Contacted']
        );
        effectiveBusinessId = newBusinessResult.insertId;
    }

    const reportTable = `${type}_reports`;
    const [reportResult] = await connection.execute(
        `INSERT INTO ${reportTable} (user_id, business_name, contact_person, contact_position, ${timeField}, photo_proof, outcome, notes, business_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [req.user.id, business_name, contact_person, contact_position, activityTime, photo_path, outcome, notes, effectiveBusinessId]
    );

    return reportResult.insertId;
}

app.post('/api/reports/cold-calling', authenticateToken, upload.single('photo_proof'), async (req, res) => {
    let connection;
    try {
        connection = await pool.getConnection();
        const reportId = await handleReportSubmission(connection, 'cold_calling', req);
        res.status(201).json({ id: reportId, message: 'Report submitted successfully' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    } finally {
        if (connection) connection.release();
    }
});

app.get('/api/reports', authenticateToken, async (req, res) => {
    let connection;
    try {
        connection = await pool.getConnection();
        const [reports] = await connection.execute('SELECT * FROM comprehensive_reports ORDER BY activity_time DESC');
        res.json({ reports });
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch reports' });
    } finally {
        if (connection) connection.release();
    }
});

// --- TASK ROUTES ---
app.post('/api/tasks/bulk-assign', authenticateToken, requireAdmin, async (req, res) => {
    let connection;
    try {
        const { business_ids, assigned_to, due_date } = req.body;
        if (!business_ids || !Array.isArray(business_ids) || !assigned_to) {
            return res.status(400).json({ error: 'Required fields are missing.' });
        }
        connection = await pool.getConnection();
        const [businesses] = await connection.execute('SELECT id, business_name FROM businesses WHERE id IN (?)', [business_ids]);

        const tasks = businesses.map(b => [
            `Follow-up with: ${b.business_name}`, assigned_to, req.user.id, b.id, 'follow_up', due_date || null
        ]);
        
        if (tasks.length > 0) {
            await connection.query('INSERT INTO tasks (title, assigned_to, assigned_by, business_id, task_type, due_date) VALUES ?', [tasks]);
        }
        res.status(201).json({ message: `${tasks.length} tasks created successfully.` });
    } catch (error) {
        res.status(500).json({ error: 'Failed to create tasks.' });
    } finally {
        if (connection) connection.release();
    }
});


// --- FOLLOW-UP & DASHBOARD ROUTES ---
app.get('/api/follow-ups', authenticateToken, async (req, res) => {
    let connection;
    try {
        connection = await pool.getConnection();
        const [followUps] = await connection.execute('SELECT f.*, b.business_name FROM follow_ups f JOIN businesses b ON f.business_id = b.id WHERE f.status = "scheduled" ORDER BY f.scheduled_date ASC');
        res.json(followUps);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch follow-ups' });
    } finally {
        if (connection) connection.release();
    }
});

// FIX: Rewritten dashboard endpoint for correctness and simplicity
app.get('/api/dashboard/stats', authenticateToken, async (req, res) => {
    let connection;
    try {
        connection = await pool.getConnection();
        const userFilter = req.user.role === 'admin' ? '' : `WHERE user_id = ${req.user.id}`;
        
        const [[{ total_visits }]] = await connection.execute(`SELECT COUNT(*) as total_visits FROM cold_calling_reports ${userFilter}`);
        const [[{ total_calls }]] = await connection.execute(`SELECT COUNT(*) as total_calls FROM telemarketing_reports ${userFilter}`);
        const [[{ deals_closed }]] = await connection.execute(`SELECT COUNT(*) as deals_closed FROM comprehensive_reports WHERE outcome = 'Deal Closed' ${req.user.role === 'admin' ? '' : `AND user_id = ${req.user.id}`}`);
        const [[{ today_activity }]] = await connection.execute(`SELECT COUNT(*) as today_activity FROM comprehensive_reports WHERE DATE(activity_time) = CURDATE() ${req.user.role === 'admin' ? '' : `AND user_id = ${req.user.id}`}`);

        res.json({
            total_visits,
            total_calls,
            deals_closed,
            today_activity
        });
    } catch (error) {
        console.error("Dashboard stats error:", error);
        res.status(500).json({ error: 'Failed to fetch dashboard statistics' });
    } finally {
        if (connection) connection.release();
    }
});


// Start server
app.listen(PORT, '0.0.0.0', () => {
    console.log(`✅ Orbyte Sales API Server running on port ${PORT}`);
});
