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
app.use('/uploads', express.static('uploads'));

// Ensure uploads directory exists
if (!fs.existsSync('uploads')) {
    fs.mkdirSync('uploads', { recursive: true });
}

// Database configuration
const poolConfig = {
    host: process.env.DB_HOST || '193.203.168.132',
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    port: 3306,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
    acquireTimeout: 60000,
    timeout: 60000,
    multipleStatements: false,
    ssl: false // Set to true if your DB requires SSL
};

// Create connection pool
const pool = mysql.createPool(poolConfig);

// Database connection status
let dbConnectionStatus = 'unknown';

async function testConnection() {
    try {
        const connection = await pool.getConnection();
        await connection.ping();
        connection.release();
        
        dbConnectionStatus = 'connected';
        console.log('✅ Database connection established');
        
    } catch (error) {
        dbConnectionStatus = 'error: ' + error.message;
        console.error('❌ Database connection failed:', error.message);
        setTimeout(testConnection, 10000); // Retry connection
    }
}

// Initialize database connection
testConnection();

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
        if (file.mimetype.startsWith('image/') || file.mimetype === 'text/csv' || file.mimetype === 'application/vnd.ms-excel') {
            cb(null, true);
        } else {
            cb(new Error('Only image and CSV files are allowed!'), false);
        }
    },
    limits: {
        fileSize: 10 * 1024 * 1024 // 10MB limit
    }
});

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'orbyte_sales_secret_key_2025';

// Health check endpoint
app.get('/api/health', (req, res) => {
    res.json({
        status: 'OK',
        message: 'Orbyte Sales API is running',
        timestamp: new Date().toISOString(),
        database: dbConnectionStatus
    });
});

// Root endpoint
app.get('/', (req, res) => {
    res.json({ 
        message: 'Orbyte Sales API Server',
        status: 'Running',
        version: '2.1.0', // Updated Version
        endpoints: {
            health: '/api/health',
            auth: '/api/auth/*',
            users: '/api/users/*',
            reports: '/api/reports/*',
            businesses: '/api/businesses/*',
            goals: '/api/goals/*',
            tasks: '/api/tasks/*',
            notifications: '/api/notifications/*',
            dashboard: '/api/dashboard/*'
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
    if (dbConnectionStatus.startsWith('error:')) {
        return res.status(503).json({ error: 'Database connection not available' });
    }
    next();
};

// Auth Routes
app.post('/api/auth/login', requireDB, async (req, res) => {
    let connection;
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password are required' });
        }

        connection = await pool.getConnection();
        
        const [users] = await connection.execute(
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

        // Update last login after successful password check
        await connection.execute(
            'UPDATE users SET last_login = NOW() WHERE id = ?',
            [user.id]
        );

        const token = jwt.sign(
            { 
                id: user.id, 
                email: user.email, 
                role: user.role,
                name: user.name,
                executive_type: user.executive_type,
                department: user.department
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
                executive_type: user.executive_type,
                department: user.department
            }
        });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Login failed' });
    } finally {
        if (connection) connection.release();
    }
});

// =============================================================================
// USER MANAGEMENT ROUTES
// =============================================================================

app.get('/api/users', authenticateToken, requireAdmin, requireDB, async (req, res) => {
    let connection;
    try {
        connection = await pool.getConnection();
        const [users] = await connection.execute(`
            SELECT id, name, email, role, executive_type, department, phone, 
                   hire_date, status, last_login, created_at 
            FROM users 
            ORDER BY created_at DESC
        `);
        res.json(users);
    } catch (error) {
        console.error('Get users error:', error);
        res.status(500).json({ error: 'Failed to fetch users' });
    } finally {
        if (connection) connection.release();
    }
});

app.post('/api/users', authenticateToken, requireAdmin, requireDB, async (req, res) => {
    let connection;
    try {
        const { name, email, password, role, executive_type, department, phone } = req.body;

        if (!name || !email || !password || !role) {
            return res.status(400).json({ error: 'Name, email, password, and role are required' });
        }

        // Validate role
        if (!['admin', 'user'].includes(role)) {
            return res.status(400).json({ error: 'Invalid role. Must be admin or user.' });
        }

        // **FIXED**: Expanded validation to match DB schema
        const validExecTypes = ['indoor', 'outdoor', 'cold_caller', 'telemarketer', null, ''];
        if (!validExecTypes.includes(executive_type)) {
            return res.status(400).json({ error: 'Invalid executive type.' });
        }

        connection = await pool.getConnection();

        // Check if user already exists
        const [existingUsers] = await connection.execute('SELECT id FROM users WHERE email = ?', [email]);
        if (existingUsers.length > 0) {
            return res.status(409).json({ error: 'User with this email already exists' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const [result] = await connection.execute(`
            INSERT INTO users (name, email, \`password\`, role, executive_type, department, phone, hire_date, status) 
            VALUES (?, ?, ?, ?, ?, ?, ?, CURDATE(), "active")
        `, [
            name, 
            email, 
            hashedPassword, 
            role, 
            executive_type || null,
            department || 'Sales',
            phone || null
        ]);

        res.status(201).json({ id: result.insertId, message: 'User created successfully' });

    } catch (error) {
        console.error('Create user error:', error);
        res.status(500).json({ error: 'Failed to create user' });
    } finally {
        if (connection) connection.release();
    }
});

app.put('/api/users/:id', authenticateToken, requireAdmin, requireDB, async (req, res) => {
    let connection;
    try {
        const { id } = req.params;
        const { name, email, role, executive_type, department, phone, status, password } = req.body;

        if (role && !['admin', 'user'].includes(role)) {
            return res.status(400).json({ error: 'Invalid role.' });
        }

        // **FIXED**: Expanded validation to match DB schema
        const validExecTypes = ['indoor', 'outdoor', 'cold_caller', 'telemarketer', null, ''];
        if (executive_type !== undefined && !validExecTypes.includes(executive_type)) {
            return res.status(400).json({ error: 'Invalid executive type.' });
        }

        connection = await pool.getConnection();

        let updateQuery = 'UPDATE users SET name = ?, email = ?, role = ?, executive_type = ?, department = ?, phone = ?, status = ?';
        let params = [name, email, role, executive_type || null, department, phone, status];

        if (password) {
            const hashedPassword = await bcrypt.hash(password, 10);
            updateQuery += ', `password` = ?';
            params.push(hashedPassword);
        }

        updateQuery += ' WHERE id = ?';
        params.push(id);

        const [result] = await connection.execute(updateQuery, params);
        if (result.affectedRows === 0) {
            return res.status(404).json({ error: 'User not found' });
        }
        res.json({ message: 'User updated successfully' });

    } catch (error) {
        console.error('Update user error:', error);
        res.status(500).json({ error: 'Failed to update user' });
    } finally {
        if (connection) connection.release();
    }
});

// Using soft delete (setting status to inactive) is better than hard delete.
// This route is fine. No changes needed.
app.delete('/api/users/:id', authenticateToken, requireAdmin, requireDB, async (req, res) => {
    let connection;
    try {
        const { id } = req.params;
        if (parseInt(id) === req.user.id) {
            return res.status(400).json({ error: 'Cannot deactivate your own account' });
        }
        connection = await pool.getConnection();
        await connection.execute('UPDATE users SET status = "inactive" WHERE id = ?', [id]);
        res.json({ message: 'User deactivated successfully' });
    } catch (error) {
        console.error('Deactivate user error:', error);
        res.status(500).json({ error: 'Failed to deactivate user' });
    } finally {
        if (connection) connection.release();
    }
});

// =============================================================================
// BUSINESS MANAGEMENT ROUTES
// =============================================================================

// The existing business routes are well-structured. No major changes needed here.
app.get('/api/businesses', authenticateToken, requireDB, async (req, res) => {
    let connection;
    try {
        const { search, status, assigned_to, industry, priority } = req.query;
        let conditions = [];
        let params = [];

        if (search) {
            conditions.push('(b.business_name LIKE ? OR b.contact_person LIKE ?)');
            params.push(`%${search}%`, `%${search}%`);
        }
        if (status) {
            conditions.push('b.status = ?');
            params.push(status);
        }
        if (assigned_to) {
            conditions.push('b.assigned_to = ?');
            params.push(assigned_to);
        }
        if (industry) {
            conditions.push('b.industry = ?');
            params.push(industry);
        }
        if (priority) {
            conditions.push('b.priority = ?');
            params.push(priority);
        }

        if (req.user.role !== 'admin') {
            conditions.push('(b.assigned_to = ? OR b.created_by = ?)');
            params.push(req.user.id, req.user.id);
        }

        const whereClause = conditions.length > 0 ? 'WHERE ' + conditions.join(' AND ') : '';

        connection = await pool.getConnection();
        const [businesses] = await connection.execute(`
            SELECT b.*, 
                   u.name as assigned_user_name,
                   creator.name as created_by_name
            FROM businesses b
            LEFT JOIN users u ON b.assigned_to = u.id
            LEFT JOIN users creator ON b.created_by = creator.id
            ${whereClause}
            ORDER BY b.created_at DESC
            LIMIT 100
        `, params);
        res.json(businesses);
    } catch (error) {
        console.error('Get businesses error:', error);
        res.status(500).json({ error: 'Failed to fetch businesses' });
    } finally {
        if (connection) connection.release();
    }
});

app.post('/api/businesses', authenticateToken, requireDB, async (req, res) => {
    let connection;
    try {
        const {
            business_name, contact_person, contact_position, phone, email, address,
            city, state, postal_code, industry, business_size, priority, assigned_to, notes
        } = req.body;

        if (!business_name) {
            return res.status(400).json({ error: 'Business name is required' });
        }

        connection = await pool.getConnection();
        
        const [result] = await connection.execute(`
            INSERT INTO businesses (business_name, contact_person, contact_position, phone, email, address, city, state, postal_code, industry, business_size, priority, assigned_to, created_by, notes, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'New')
        `, [
            business_name, contact_person || null, contact_position || null, phone || null, email || null, address || null, city || null, state || null, postal_code || null, industry || null, business_size || 'Small', priority || 'Medium', assigned_to || null, req.user.id, notes || null
        ]);

        res.status(201).json({ id: result.insertId, message: 'Business created successfully' });
    } catch (error) {
        console.error('Create business error:', error);
        res.status(500).json({ error: 'Failed to create business' });
    } finally {
        if (connection) connection.release();
    }
});

app.put('/api/businesses/:id', authenticateToken, requireDB, async (req, res) => {
    let connection;
    try {
        const { id } = req.params;
        const {
            business_name, contact_person, contact_position, phone, email, address,
            city, state, postal_code, industry, business_size, priority, assigned_to, 
            status, notes
        } = req.body;

        connection = await pool.getConnection();
        
        // Non-admins can only edit businesses assigned to them
        if (req.user.role !== 'admin') {
            const [business] = await connection.execute('SELECT assigned_to FROM businesses WHERE id = ?', [id]);
            if (business.length === 0 || business[0].assigned_to !== req.user.id) {
                return res.status(403).json({ error: 'Access denied. You can only edit businesses assigned to you.' });
            }
        }

        await connection.execute(`
            UPDATE businesses SET business_name = ?, contact_person = ?, contact_position = ?, phone = ?, email = ?, address = ?, city = ?, state = ?, postal_code = ?, industry = ?, business_size = ?, priority = ?, assigned_to = ?, status = ?, notes = ?
            WHERE id = ?
        `, [
            business_name, contact_person, contact_position, phone, email, address,
            city, state, postal_code, industry, business_size, priority, 
            assigned_to, status, notes, id
        ]);
        res.json({ message: 'Business updated successfully' });
    } catch (error) {
        console.error('Update business error:', error);
        res.status(500).json({ error: 'Failed to update business' });
    } finally {
        if (connection) connection.release();
    }
});

// =============================================================================
// REPORT ROUTES
// =============================================================================

// Shared function to handle report submission logic
async function handleReportSubmission(connection, type, req) {
    const {
        business_name, contact_person, contact_position, outcome, notes,
        latitude, longitude, business_id, follow_up_required, follow_up_date
    } = req.body;

    const timeField = type === 'cold_calling' ? 'visit_time' : 'call_time';
    const activityTime = req.body[timeField];
    const photo_path = req.file ? req.file.filename : null;

    // **FIXED**: Validate outcome against a predefined list
    const validOutcomes = ['Deal Closed', 'Appointment Scheduled', 'Not Interested', 'Follow-up Needed', 'Other'];
    if (!business_name || !contact_person || !activityTime || !outcome || !validOutcomes.includes(outcome)) {
        throw new Error('Required fields are missing or invalid.');
    }

    const activityDateTime = new Date(activityTime).toISOString().slice(0, 19).replace('T', ' ');

    let effectiveBusinessId = business_id;

    // **IMPROVEMENT**: Auto-create business if it doesn't exist
    if (!effectiveBusinessId || effectiveBusinessId === 'null' || effectiveBusinessId === '') {
        const [existingBusiness] = await connection.execute('SELECT id FROM businesses WHERE business_name = ?', [business_name]);
        if (existingBusiness.length > 0) {
            effectiveBusinessId = existingBusiness[0].id;
        } else {
            const [newBusinessResult] = await connection.execute(`
                INSERT INTO businesses (business_name, contact_person, contact_position, created_by, assigned_to, status)
                VALUES (?, ?, ?, ?, ?, 'Contacted')
            `, [business_name, contact_person, contact_position, req.user.id, req.user.id]);
            effectiveBusinessId = newBusinessResult.insertId;
        }
    }

    const reportTable = `${type}_reports`;
    const reportResult = await connection.execute(`
        INSERT INTO ${reportTable} (user_id, business_name, contact_person, contact_position, ${timeField}, ${type === 'cold_calling' ? 'photo_proof,' : ''} outcome, notes, ${type === 'cold_calling' ? 'latitude, longitude,' : ''} business_id, follow_up_required, follow_up_date)
        VALUES (?, ?, ?, ?, ?, ${type === 'cold_calling' ? '?,' : ''} ?, ?, ${type === 'cold_calling' ? '?, ?,' : ''} ?, ?, ?)
    `, [
        req.user.id, business_name, contact_person, contact_position, activityDateTime,
        ...(type === 'cold_calling' ? [photo_path] : []),
        outcome, notes || null,
        ...(type === 'cold_calling' ? [latitude || null, longitude || null] : []),
        effectiveBusinessId, follow_up_required === 'true', follow_up_date || null
    ]);
    const reportId = reportResult[0].insertId;

    // Add to business interactions
    await connection.execute(`
        INSERT INTO business_interactions (business_id, user_id, interaction_type, outcome, notes, interaction_date)
        VALUES (?, ?, ?, ?, ?, ?)
    `, [effectiveBusinessId, req.user.id, type.replace('_', ''), outcome, notes || null, activityDateTime]);

    // Update business status
    if (outcome === 'Deal Closed' || outcome === 'Appointment Scheduled') {
        await connection.execute('UPDATE businesses SET status = ? WHERE id = ?', [outcome, effectiveBusinessId]);
    } else {
        await connection.execute('UPDATE businesses SET status = "Contacted" WHERE id = ?', [effectiveBusinessId]);
    }
    
    // Create follow-up if required
    if (follow_up_required === 'true' && follow_up_date) {
        await connection.execute(`
            INSERT INTO follow_ups (business_id, user_id, report_id, report_type, follow_up_type, scheduled_date, notes)
            VALUES (?, ?, ?, ?, 'call', ?, ?)
        `, [effectiveBusinessId, req.user.id, reportId, type, follow_up_date, `Follow-up from ${type.replace('_', ' ')}`]);
    }
    
    // Update goal progress
    await updateGoalProgress(connection, req.user.id, type, outcome);
    
    return reportId;
}

app.post('/api/reports/cold-calling', authenticateToken, requireDB, upload.single('photo_proof'), async (req, res) => {
    let connection;
    try {
        connection = await pool.getConnection();
        await connection.beginTransaction();
        const reportId = await handleReportSubmission(connection, 'cold_calling', req);
        await connection.commit();
        res.status(201).json({ id: reportId, message: 'Cold calling report submitted successfully' });
    } catch (error) {
        if (connection) await connection.rollback();
        console.error('Submit cold calling report error:', error);
        res.status(500).json({ error: error.message || 'Failed to submit report' });
    } finally {
        if (connection) connection.release();
    }
});

app.post('/api/reports/telemarketing', authenticateToken, requireDB, async (req, res) => {
    let connection;
    try {
        connection = await pool.getConnection();
        await connection.beginTransaction();
        const reportId = await handleReportSubmission(connection, 'telemarketing', req);
        await connection.commit();
        res.status(201).json({ id: reportId, message: 'Telemarketing report submitted successfully' });
    } catch (error) {
        if (connection) await connection.rollback();
        console.error('Submit telemarketing report error:', error);
        res.status(500).json({ error: error.message || 'Failed to submit report' });
    } finally {
        if (connection) connection.release();
    }
});

app.get('/api/reports', authenticateToken, requireDB, async (req, res) => {
    let connection;
    try {
        const { date_from, date_to, outcome, business_name, report_type, user_id, page = 1, limit = 50 } = req.query;
        let conditions = [];
        let params = [];
        
        if (req.user.role !== 'admin') {
            conditions.push('user_id = ?');
            params.push(req.user.id);
        } else if (user_id) {
            conditions.push('user_id = ?');
            params.push(user_id);
        }
        if (date_from) { conditions.push('DATE(activity_time) >= ?'); params.push(date_from); }
        if (date_to) { conditions.push('DATE(activity_time) <= ?'); params.push(date_to); }
        if (outcome) { conditions.push('outcome = ?'); params.push(outcome); }
        if (business_name) { conditions.push('business_name LIKE ?'); params.push(`%${business_name}%`); }
        if (report_type) { conditions.push('report_type = ?'); params.push(report_type); }

        const whereClause = conditions.length > 0 ? 'WHERE ' + conditions.join(' AND ') : '';
        const offset = (page - 1) * limit;

        connection = await pool.getConnection();
        const query = `SELECT * FROM comprehensive_reports ${whereClause} ORDER BY activity_time DESC LIMIT ? OFFSET ?`;
        params.push(parseInt(limit), offset);
        const [reports] = await connection.execute(query, params);

        const countQuery = `SELECT COUNT(*) as total FROM comprehensive_reports ${whereClause}`;
        const [countResult] = await connection.execute(countQuery, params.slice(0, -2));
        const total = countResult[0].total;

        res.json({
            reports,
            pagination: {
                page: parseInt(page),
                limit: parseInt(limit),
                total,
                pages: Math.ceil(total / limit)
            }
        });
    } catch (error) {
        console.error('Get reports error:', error);
        res.status(500).json({ error: 'Failed to fetch reports' });
    } finally {
        if (connection) connection.release();
    }
});

app.get('/api/reports/:type/:id', authenticateToken, requireDB, async (req, res) => {
    let connection;
    try {
        const { type, id } = req.params;
        if (!['cold_calling', 'telemarketing'].includes(type)) {
            return res.status(400).json({ error: 'Invalid report type' });
        }
        connection = await pool.getConnection();
        const [reports] = await connection.execute(`
            SELECT cr.*, b.address as linked_address
            FROM comprehensive_reports cr
            LEFT JOIN businesses b ON cr.business_id = b.id
            WHERE cr.report_type = ? AND cr.id = ?
        `, [type, id]);
        if (reports.length === 0) return res.status(404).json({ error: 'Report not found' });

        const report = reports[0];
        if (req.user.role !== 'admin' && report.user_id !== req.user.id) {
            return res.status(403).json({ error: 'Access denied' });
        }
        res.json(report);
    } catch (error) {
        console.error('Get report details error:', error);
        res.status(500).json({ error: 'Failed to fetch report details' });
    } finally {
        if (connection) connection.release();
    }
});

app.get('/api/reports/photo/:filename', authenticateToken, (req, res) => {
    const { filename } = req.params;
    const photoPath = path.join(__dirname, 'uploads', filename);
    if (fs.existsSync(photoPath)) {
        res.sendFile(photoPath);
    } else {
        res.status(404).json({ error: 'Photo not found' });
    }
});

app.get('/api/reports/export', authenticateToken, requireAdmin, requireDB, async (req, res) => {
    let connection;
    try {
        connection = await pool.getConnection();
        const [allReports] = await connection.execute(`
            SELECT report_type, user_name, department, business_name, contact_person, contact_position, activity_time, outcome, notes, created_at, latitude, longitude, photo_proof, follow_up_required, follow_up_date
            FROM comprehensive_reports ORDER BY created_at DESC
        `);
        if (allReports.length === 0) return res.status(404).json({ error: 'No reports found' });

        const csvHeaders = Object.keys(allReports[0]).join(',');
        const csvRows = allReports.map(row => 
            Object.values(row).map(val => `"${String(val || '').replace(/"/g, '""')}"`).join(',')
        ).join('\n');
        
        res.setHeader('Content-Type', 'text/csv');
        res.setHeader('Content-Disposition', `attachment; filename="orbyte_sales_reports_${new Date().toISOString().split('T')[0]}.csv"`);
        res.send(csvHeaders + '\n' + csvRows);
    } catch (error) {
        console.error('Export reports error:', error);
        res.status(500).json({ error: 'Failed to export reports' });
    } finally {
        if (connection) connection.release();
    }
});

// =============================================================================
// GOALS, TASKS, FOLLOW-UPS (Routes are mostly fine, just ensuring they work with new frontend)
// =============================================================================
app.get('/api/goals', authenticateToken, requireDB, async (req, res) => {
    let connection;
    try {
        let query = 'SELECT g.*, u.name as user_name FROM goals g JOIN users u ON g.user_id = u.id';
        let params = [];

        if (req.user.role !== 'admin') {
            query += ' WHERE g.user_id = ?';
            params.push(req.user.id);
        }
        query += ' ORDER BY g.end_date DESC';
        connection = await pool.getConnection();
        const [goals] = await connection.execute(query, params);
        res.json(goals);
    } catch (error) {
        console.error('Get goals error:', error);
        res.status(500).json({ error: 'Failed to fetch goals' });
    } finally {
        if (connection) connection.release();
    }
});
app.post('/api/goals', authenticateToken, requireAdmin, requireDB, async (req, res) => {
    let connection;
    try {
        const { user_id, goal_type, activity_type, target_value, start_date, end_date } = req.body;
        if (!user_id || !goal_type || !activity_type || !target_value || !start_date || !end_date) {
            return res.status(400).json({ error: 'All fields are required' });
        }
        connection = await pool.getConnection();
        const [result] = await connection.execute(
            'INSERT INTO goals (user_id, goal_type, activity_type, target_value, start_date, end_date) VALUES (?, ?, ?, ?, ?, ?)',
            [user_id, goal_type, activity_type, target_value, start_date, end_date]
        );
        res.status(201).json({ id: result.insertId, message: 'Goal created successfully' });
    } catch (error) {
        console.error('Create goal error:', error);
        res.status(500).json({ error: 'Failed to create goal' });
    } finally {
        if (connection) connection.release();
    }
});
app.get('/api/tasks', authenticateToken, requireDB, async (req, res) => {
    let connection;
    try {
        const { status, assigned_to } = req.query;
        let conditions = [];
        let params = [];

        if (status) { conditions.push('t.status = ?'); params.push(status); }

        if (req.user.role !== 'admin') {
            conditions.push('(t.assigned_to = ? OR t.assigned_by = ?)');
            params.push(req.user.id, req.user.id);
        } else if (assigned_to) {
            conditions.push('t.assigned_to = ?');
            params.push(assigned_to);
        }

        const whereClause = conditions.length > 0 ? 'WHERE ' + conditions.join(' AND ') : '';
        connection = await pool.getConnection();
        const [tasks] = await connection.execute(`
            SELECT t.*, assigned_user.name as assigned_user_name, assigner.name as assigned_by_name, b.business_name
            FROM tasks t
            LEFT JOIN users assigned_user ON t.assigned_to = assigned_user.id
            LEFT JOIN users assigner ON t.assigned_by = assigner.id
            LEFT JOIN businesses b ON t.business_id = b.id
            ${whereClause} ORDER BY t.due_date ASC
        `, params);
        res.json(tasks);
    } catch (error) {
        console.error('Get tasks error:', error);
        res.status(500).json({ error: 'Failed to fetch tasks' });
    } finally {
        if (connection) connection.release();
    }
});
app.post('/api/tasks', authenticateToken, requireDB, async (req, res) => {
    let connection;
    try {
        const { title, description, assigned_to, business_id, task_type, priority, due_date, notes } = req.body;
        if (!title || !assigned_to || !task_type) {
            return res.status(400).json({ error: 'Title, assigned user, and task type are required' });
        }
        connection = await pool.getConnection();
        const [result] = await connection.execute(
            'INSERT INTO tasks (title, description, assigned_to, assigned_by, business_id, task_type, priority, due_date, notes) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
            [title, description, assigned_to, req.user.id, business_id || null, task_type, priority, due_date || null, notes]
        );
        res.status(201).json({ id: result.insertId, message: 'Task created successfully' });
    } catch (error) {
        console.error('Create task error:', error);
        res.status(500).json({ error: 'Failed to create task' });
    } finally {
        if (connection) connection.release();
    }
});
app.put('/api/tasks/:id', authenticateToken, requireDB, async (req, res) => {
    let connection;
    try {
        const { id } = req.params;
        const { status, notes, title, description, priority, due_date, assigned_to, task_type } = req.body;
        connection = await pool.getConnection();

        const [tasks] = await connection.execute('SELECT assigned_to, assigned_by FROM tasks WHERE id = ?', [id]);
        if (tasks.length === 0) return res.status(404).json({ error: 'Task not found' });
        const task = tasks[0];
        if (req.user.role !== 'admin' && task.assigned_to !== req.user.id && task.assigned_by !== req.user.id) {
            return res.status(403).json({ error: 'Access denied' });
        }
        
        let updateFields = [];
        let params = [];
        const updateData = { status, notes, title, description, priority, due_date, assigned_to, task_type };
        for (const key in updateData) {
            if (updateData[key] !== undefined) {
                updateFields.push(`${key} = ?`);
                params.push(updateData[key]);
            }
        }
        if (status === 'completed') updateFields.push('completed_at = NOW()');
        if (updateFields.length === 0) return res.status(400).json({ error: 'No fields to update' });
        
        params.push(id);
        await connection.execute(`UPDATE tasks SET ${updateFields.join(', ')} WHERE id = ?`, params);
        res.json({ message: 'Task updated successfully' });
    } catch (error) {
        console.error('Update task error:', error);
        res.status(500).json({ error: 'Failed to update task' });
    } finally {
        if (connection) connection.release();
    }
});
app.get('/api/follow-ups', authenticateToken, requireDB, async (req, res) => {
    let connection;
    try {
        let query = `
            SELECT f.*, b.business_name, u.name as user_name
            FROM follow_ups f
            LEFT JOIN businesses b ON f.business_id = b.id
            LEFT JOIN users u ON f.user_id = u.id
        `;
        let params = [];
        if (req.user.role !== 'admin') {
            query += ' WHERE f.user_id = ?';
            params.push(req.user.id);
        }
        query += ' ORDER BY f.scheduled_date ASC';
        connection = await pool.getConnection();
        const [followUps] = await connection.execute(query, params);
        res.json(followUps);
    } catch (error) {
        console.error('Get follow-ups error:', error);
        res.status(500).json({ error: 'Failed to fetch follow-ups' });
    } finally {
        if (connection) connection.release();
    }
});
app.put('/api/follow-ups/:id', authenticateToken, requireDB, async (req, res) => {
    let connection;
    try {
        const { id } = req.params;
        const { status, outcome, notes, scheduled_date } = req.body;
        connection = await pool.getConnection();
        // Permission check
        const [followUp] = await connection.execute('SELECT user_id FROM follow_ups WHERE id = ?', [id]);
        if (req.user.role !== 'admin' && (followUp.length === 0 || followUp[0].user_id !== req.user.id)) {
            return res.status(403).json({ error: 'Access denied' });
        }
        const completedAt = status === 'completed' ? new Date() : null;
        await connection.execute(
            'UPDATE follow_ups SET status = ?, outcome = ?, notes = ?, scheduled_date = ?, completed_at = ? WHERE id = ?',
            [status, outcome, notes, scheduled_date, completedAt, id]
        );
        res.json({ message: 'Follow-up updated successfully' });
    } catch (error) {
        console.error('Update follow-up error:', error);
        res.status(500).json({ error: 'Failed to update follow-up' });
    } finally {
        if (connection) connection.release();
    }
});


// =============================================================================
// DASHBOARD
// =============================================================================

app.get('/api/dashboard/stats', authenticateToken, requireDB, async (req, res) => {
    let connection;
    try {
        const userCondition = req.user.role !== 'admin' ? 'WHERE user_id = ?' : '';
        const userParam = req.user.role !== 'admin' ? [req.user.id] : [];
        connection = await pool.getConnection();

        const [activityStats] = await connection.execute(`
            SELECT
                SUM(CASE WHEN report_type = 'cold_calling' THEN 1 ELSE 0 END) as total_visits,
                SUM(CASE WHEN report_type = 'telemarketing' THEN 1 ELSE 0 END) as total_calls,
                SUM(CASE WHEN outcome = 'Deal Closed' THEN 1 ELSE 0 END) as deals_closed,
                SUM(CASE WHEN DATE(activity_time) = CURDATE() THEN 1 ELSE 0 END) as today_activity
            FROM comprehensive_reports ${userCondition}
        `, userParam);
        
        const [weeklyActivity] = await connection.execute(`
            SELECT report_type as type, DATE(activity_time) as date, COUNT(*) as count 
            FROM comprehensive_reports 
            WHERE activity_time >= DATE_SUB(CURDATE(), INTERVAL 7 DAY) 
            ${req.user.role !== 'admin' ? 'AND user_id = ?' : ''}
            GROUP BY type, date ORDER BY date DESC
        `, userParam);

        const [goalsProgress] = await connection.execute(`
            SELECT g.*,
                (SELECT COUNT(*) FROM comprehensive_reports
                 WHERE user_id = g.user_id
                   AND (g.activity_type = 'all' OR report_type = g.activity_type OR (g.activity_type = 'deals' AND outcome = 'Deal Closed'))
                   AND activity_time BETWEEN g.start_date AND g.end_date) as current_progress
            FROM goals g
            WHERE g.status = 'active'
              AND CURDATE() BETWEEN g.start_date AND g.end_date
              ${req.user.role !== 'admin' ? 'AND g.user_id = ?' : ''}
        `, userParam);

        const [taskStats] = await connection.execute(`
            SELECT COUNT(*) as pending_tasks FROM tasks
            WHERE status IN ('pending', 'in_progress') AND assigned_to = ?
        `, [req.user.id]);
        
        const [followUpStats] = await connection.execute(`
            SELECT COUNT(*) as scheduled_followups FROM follow_ups
            WHERE status = 'scheduled' AND user_id = ?
        `, [req.user.id]);

        res.json({
            stats: activityStats[0] || {},
            weeklyActivity,
            goals: goalsProgress,
            tasks: taskStats[0] || {},
            followUps: followUpStats[0] || {}
        });
    } catch (error) {
        console.error('Dashboard stats error:', error);
        res.status(500).json({ error: 'Failed to fetch dashboard statistics' });
    } finally {
        if (connection) connection.release();
    }
});


// =============================================================================
// UTILITY FUNCTIONS & SERVER START
// =============================================================================

async function updateGoalProgress(connection, userId, activityType, outcome) {
    try {
        const activity = activityType.replace('_', '');
        await connection.execute(`
            UPDATE goals SET current_value = current_value + 1
            WHERE user_id = ? AND status = 'active' AND CURDATE() BETWEEN start_date AND end_date
              AND (activity_type = 'all' OR activity_type = ?)
        `, [userId, activity]);
        if (outcome === 'Deal Closed') {
            await connection.execute(`
                UPDATE goals SET current_value = current_value + 1
                WHERE user_id = ? AND status = 'active' AND CURDATE() BETWEEN start_date AND end_date
                  AND activity_type = 'deals'
            `, [userId]);
        }
    } catch (error) {
        console.error('Error updating goal progress:', error);
        // Do not re-throw, as this is a non-critical background task
    }
}

// Error handling & 404
app.use((err, req, res, next) => {
    console.error('Unhandled Error:', err);
    res.status(500).json({ error: 'Internal server error' });
});
app.use((req, res) => {
    res.status(404).json({ error: 'Endpoint not found' });
});

// Start server
app.listen(PORT, '0.0.0.0', () => {
    console.log(`✅ Orbyte Sales API Server running on port ${PORT}`);
});
