// server.js (Updated)

const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const { Readable } = require('stream');
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
    host: process.env.DB_HOST,
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
    ssl: false 
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
const JWT_SECRET = process.env.JWT_SECRET;

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
        version: '2.2.0', // Updated Version
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

        await connection.execute(
            'UPDATE users SET last_login = NOW() WHERE id = ?',
            [user.id]
        );

        const token = jwt.sign(
            { id: user.id, email: user.email, role: user.role, name: user.name },
            JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.json({
            token,
            user: { id: user.id, name: user.name, email: user.email, role: user.role }
        });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Login failed' });
    } finally {
        if (connection) connection.release();
    }
});

// USER MANAGEMENT ROUTES (Unchanged)
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
        res.status(500).json({ error: 'Failed to fetch users' });
    } finally {
        if (connection) connection.release();
    }
});

app.post('/api/users', authenticateToken, requireAdmin, requireDB, async (req, res) => {
    let connection;
    try {
        const { name, email, password, role, executive_type, department, phone, status } = req.body;
        if (!name || !email || !password || !role) {
            return res.status(400).json({ error: 'Name, email, password, and role are required' });
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        connection = await pool.getConnection();
        const [result] = await connection.execute(`
            INSERT INTO users (name, email, \`password\`, role, executive_type, department, phone, status, hire_date) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURDATE())
        `, [name, email, hashedPassword, role, executive_type || null, department, phone, status || 'active']);
        res.status(201).json({ id: result.insertId, message: 'User created successfully' });
    } catch (error) {
        if (error.code === 'ER_DUP_ENTRY') {
             return res.status(409).json({ error: 'User with this email already exists' });
        }
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
        
        let updateQuery = 'UPDATE users SET name = ?, email = ?, role = ?, executive_type = ?, department = ?, phone = ?, status = ?';
        let params = [name, email, role, executive_type, department, phone, status];
        if (password) {
            const hashedPassword = await bcrypt.hash(password, 10);
            updateQuery += ', `password` = ?';
            params.push(hashedPassword);
        }
        updateQuery += ' WHERE id = ?';
        params.push(id);
        
        connection = await pool.getConnection();
        const [result] = await connection.execute(updateQuery, params);
        if (result.affectedRows === 0) {
            return res.status(404).json({ error: 'User not found' });
        }
        res.json({ message: 'User updated successfully' });

    } catch (error) {
        res.status(500).json({ error: 'Failed to update user' });
    } finally {
        if (connection) connection.release();
    }
});

// BUSINESS MANAGEMENT ROUTES

app.get('/api/businesses', authenticateToken, requireDB, async (req, res) => {
    let connection;
    try {
        let conditions = ["status != 'Archived'"]; // MODIFIED: Exclude archived businesses by default
        let params = [];
        if (req.user.role !== 'admin') {
            conditions.push('(b.assigned_to = ? OR b.created_by = ?)');
            params.push(req.user.id, req.user.id);
        }
        const whereClause = conditions.length > 0 ? 'WHERE ' + conditions.join(' AND ') : '';
        connection = await pool.getConnection();
        const [businesses] = await connection.execute(`
            SELECT b.*, u.name as assigned_user_name
            FROM businesses b
            LEFT JOIN users u ON b.assigned_to = u.id
            ${whereClause}
            ORDER BY b.created_at DESC
        `, params);
        res.json(businesses);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch businesses' });
    } finally {
        if (connection) connection.release();
    }
});

app.post('/api/businesses', authenticateToken, requireDB, async (req, res) => {
    let connection;
    try {
        const { business_name, contact_person, contact_position, phone, email, address, industry, priority, assigned_to, notes } = req.body;
        if (!business_name) {
            return res.status(400).json({ error: 'Business name is required' });
        }
        connection = await pool.getConnection();
        const [result] = await connection.execute(`
            INSERT INTO businesses (business_name, contact_person, contact_position, phone, email, address, industry, priority, assigned_to, created_by, notes, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'New')
        `, [business_name, contact_person, contact_position, phone, email, address, industry, priority, assigned_to || null, req.user.id, notes]);
        res.status(201).json({ id: result.insertId, message: 'Business created successfully' });
    } catch (error) {
        res.status(500).json({ error: 'Failed to create business' });
    } finally {
        if (connection) connection.release();
    }
});

app.put('/api/businesses/:id', authenticateToken, requireDB, async (req, res) => {
    let connection;
    try {
        const { id } = req.params;
        const { business_name, contact_person, contact_position, phone, email, address, industry, priority, assigned_to, status, notes } = req.body;
        connection = await pool.getConnection();
        await connection.execute(`
            UPDATE businesses SET business_name = ?, contact_person = ?, contact_position = ?, phone = ?, email = ?, address = ?, industry = ?, priority = ?, assigned_to = ?, status = ?, notes = ?
            WHERE id = ?
        `, [business_name, contact_person, contact_position, phone, email, address, industry, priority, assigned_to, status, notes, id]);
        res.json({ message: 'Business updated successfully' });
    } catch (error) {
        res.status(500).json({ error: 'Failed to update business' });
    } finally {
        if (connection) connection.release();
    }
});

// NEW: Endpoint for soft-deleting a business
app.delete('/api/businesses/:id', authenticateToken, requireAdmin, requireDB, async (req, res) => {
    let connection;
    try {
        const { id } = req.params;
        connection = await pool.getConnection();
        await connection.execute(`UPDATE businesses SET status = 'Archived' WHERE id = ?`, [id]);
        res.json({ message: 'Business archived successfully' });
    } catch (error) {
        console.error('Archive business error:', error);
        res.status(500).json({ error: 'Failed to archive business' });
    } finally {
        if (connection) connection.release();
    }
});

// NEW: Endpoint for bulk business upload
app.post('/api/businesses/upload', authenticateToken, requireAdmin, requireDB, upload.single('business_csv'), async (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: 'No file uploaded.' });
    }

    let connection;
    try {
        const businesses = [];
        const buffer = req.file.buffer.toString('utf-8');
        const rows = buffer.split('\n').slice(1); // Assuming first row is header

        for (const row of rows) {
            if (!row) continue;
            const [business_name, contact_person, phone, email, address] = row.split(',').map(item => item.trim());
            if (business_name) {
                businesses.push([
                    business_name, contact_person || null, phone || null, email || null, address || null, req.user.id
                ]);
            }
        }
        
        if (businesses.length === 0) {
            return res.status(400).json({ error: 'CSV file is empty or invalid.' });
        }

        connection = await pool.getConnection();
        await connection.query(`
            INSERT INTO businesses (business_name, contact_person, phone, email, address, created_by) VALUES ?
        `, [businesses]);

        res.status(201).json({ message: `${businesses.length} businesses uploaded successfully.` });

    } catch (error) {
        console.error('Bulk upload error:', error);
        res.status(500).json({ error: 'Failed to process CSV file.' });
    } finally {
        if (connection) connection.release();
        // Clean up uploaded file
        fs.unlinkSync(req.file.path);
    }
});


// REPORT ROUTES
async function handleReportSubmission(connection, type, req) {
    const { business_name, contact_person, contact_position, outcome, notes, latitude, longitude, business_id } = req.body;
    const timeField = type === 'cold_calling' ? 'visit_time' : 'call_time';
    const activityTime = req.body[timeField];
    const photo_path = req.file ? req.file.filename : null;

    // MODIFIED: Unified outcome validation
    const validOutcomes = ['Deal Closed', 'Follow-up Required', 'Not Interested', 'No Response', 'Appointment Scheduled'];
    if (!business_name || !contact_person || !activityTime || !outcome || !validOutcomes.includes(outcome)) {
        throw new Error('Required fields are missing or invalid.');
    }
    
    // Logic to find or create business remains the same
    let effectiveBusinessId = business_id;
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
    const reportFields = ['user_id', 'business_name', 'contact_person', 'contact_position', timeField, 'outcome', 'notes', 'business_id'];
    const reportValues = [req.user.id, business_name, contact_person, contact_position, activityTime, outcome, notes, effectiveBusinessId];
    
    if (type === 'cold_calling') {
        reportFields.push('photo_proof', 'latitude', 'longitude');
        reportValues.push(photo_path, latitude, longitude);
    }
    
    const placeholders = reportValues.map(() => '?').join(', ');
    const [reportResult] = await connection.execute(`
        INSERT INTO ${reportTable} (${reportFields.join(', ')}) VALUES (${placeholders})
    `, reportValues);
    
    return reportResult.insertId;
}

app.post('/api/reports/cold-calling', authenticateToken, requireDB, upload.single('photo_proof'), async (req, res) => {
    let connection;
    try {
        connection = await pool.getConnection();
        const reportId = await handleReportSubmission(connection, 'cold_calling', req);
        res.status(201).json({ id: reportId, message: 'Cold calling report submitted successfully' });
    } catch (error) {
        res.status(500).json({ error: error.message || 'Failed to submit report' });
    } finally {
        if (connection) connection.release();
    }
});

app.post('/api/reports/telemarketing', authenticateToken, requireDB, upload.none(), async (req, res) => { // Using upload.none() for consistency
    let connection;
    try {
        connection = await pool.getConnection();
        const reportId = await handleReportSubmission(connection, 'telemarketing', req);
        res.status(201).json({ id: reportId, message: 'Telemarketing report submitted successfully' });
    } catch (error) {
        res.status(500).json({ error: error.message || 'Failed to submit report' });
    } finally {
        if (connection) connection.release();
    }
});


// ... Other report routes remain largely the same ...
app.get('/api/reports', authenticateToken, requireDB, async (req, res) => {
    let connection;
    try {
        const { date_from, date_to, outcome, report_type, page = 1, limit = 15 } = req.query;
        let conditions = [];
        let params = [];
        
        if (req.user.role !== 'admin') {
            conditions.push('user_id = ?');
            params.push(req.user.id);
        }
        if (date_from) { conditions.push('DATE(activity_time) >= ?'); params.push(date_from); }
        if (date_to) { conditions.push('DATE(activity_time) <= ?'); params.push(date_to); }
        if (outcome) { conditions.push('outcome = ?'); params.push(outcome); }
        if (report_type) { conditions.push('report_type = ?'); params.push(report_type); }

        const whereClause = conditions.length > 0 ? 'WHERE ' + conditions.join(' AND ') : '';
        const offset = (page - 1) * limit;

        connection = await pool.getConnection();
        const query = `SELECT * FROM comprehensive_reports ${whereClause} ORDER BY activity_time DESC LIMIT ? OFFSET ?`;
        const queryParams = [...params, parseInt(limit), parseInt(offset)];
        const [reports] = await connection.execute(query, queryParams);

        const countQuery = `SELECT COUNT(*) as total FROM comprehensive_reports ${whereClause}`;
        const [countResult] = await connection.execute(countQuery, params);
        const total = countResult[0].total;

        res.json({
            reports,
            pagination: { page: parseInt(page), limit: parseInt(limit), total, pages: Math.ceil(total / limit) }
        });
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch reports' });
    } finally {
        if (connection) connection.release();
    }
});

app.get('/api/reports/:type/:id', authenticateToken, requireDB, async (req, res) => {
    let connection;
    try {
        const { type, id } = req.params;
        connection = await pool.getConnection();
        const [reports] = await connection.execute('SELECT * FROM comprehensive_reports WHERE report_type = ? AND id = ?', [type, id]);
        if (reports.length === 0) return res.status(404).json({ error: 'Report not found' });
        res.json(reports[0]);
    } catch (error) {
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
        const [allReports] = await connection.execute(`SELECT * FROM comprehensive_reports ORDER BY activity_time DESC`);
        if (allReports.length === 0) return res.status(404).json({ error: 'No reports found' });

        const csvHeaders = Object.keys(allReports[0]).join(',');
        const csvRows = allReports.map(row => Object.values(row).map(val => `"${String(val || '').replace(/"/g, '""')}"`).join(',')).join('\n');
        
        res.setHeader('Content-Type', 'text/csv');
        res.setHeader('Content-Disposition', `attachment; filename="orbyte_sales_reports_${new Date().toISOString().split('T')[0]}.csv"`);
        res.send(csvHeaders + '\n' + csvRows);
    } catch (error) {
        res.status(500).json({ error: 'Failed to export reports' });
    } finally {
        if (connection) connection.release();
    }
});


// TASKS ROUTES
app.get('/api/tasks', authenticateToken, requireDB, async (req, res) => {
    let connection;
    try {
        const { status, assigned_to } = req.query;
        let conditions = [];
        let params = [];

        if (status) { conditions.push('t.status = ?'); params.push(status); }
        if (req.user.role !== 'admin') {
            conditions.push('t.assigned_to = ?');
            params.push(req.user.id);
        } else if (assigned_to) {
            conditions.push('t.assigned_to = ?');
            params.push(assigned_to);
        }

        const whereClause = conditions.length > 0 ? 'WHERE ' + conditions.join(' AND ') : '';
        connection = await pool.getConnection();
        const [tasks] = await connection.execute(`
            SELECT t.*, u_assigned.name as assigned_user_name, u_creator.name as assigned_by_name, b.business_name
            FROM tasks t
            LEFT JOIN users u_assigned ON t.assigned_to = u_assigned.id
            LEFT JOIN users u_creator ON t.assigned_by = u_creator.id
            LEFT JOIN businesses b ON t.business_id = b.id
            ${whereClause} ORDER BY t.due_date ASC
        `, params);
        res.json(tasks);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch tasks' });
    } finally {
        if (connection) connection.release();
    }
});

app.post('/api/tasks', authenticateToken, requireAdmin, requireDB, async (req, res) => {
    let connection;
    try {
        const { title, description, assigned_to, business_id, task_type, priority, due_date } = req.body;
        if (!title || !assigned_to || !task_type) {
            return res.status(400).json({ error: 'Title, assigned user, and task type are required' });
        }
        connection = await pool.getConnection();
        const [result] = await connection.execute(
            'INSERT INTO tasks (title, description, assigned_to, assigned_by, business_id, task_type, priority, due_date) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
            [title, description, assigned_to, req.user.id, business_id || null, task_type, priority, due_date]
        );
        res.status(201).json({ id: result.insertId, message: 'Task created successfully' });
    } catch (error) {
        res.status(500).json({ error: 'Failed to create task' });
    } finally {
        if (connection) connection.release();
    }
});

// NEW: Endpoint for bulk task assignment
app.post('/api/tasks/bulk-assign', authenticateToken, requireAdmin, requireDB, async (req, res) => {
    let connection;
    try {
        const { business_ids, assigned_to, title_prefix, due_date } = req.body;

        if (!business_ids || !Array.isArray(business_ids) || business_ids.length === 0 || !assigned_to) {
            return res.status(400).json({ error: 'Business IDs and assigned user are required.' });
        }

        connection = await pool.getConnection();
        const tasks = [];
        const [businesses] = await connection.execute('SELECT id, business_name FROM businesses WHERE id IN (?)', [business_ids]);

        for (const business of businesses) {
            const title = `${title_prefix || 'Follow-up with'}: ${business.business_name}`;
            tasks.push([
                title, assigned_to, req.user.id, business.id, 'follow_up', 'Medium', due_date || null
            ]);
        }
        
        if (tasks.length > 0) {
            await connection.query(
                'INSERT INTO tasks (title, assigned_to, assigned_by, business_id, task_type, priority, due_date) VALUES ?',
                [tasks]
            );
        }

        res.status(201).json({ message: `${tasks.length} tasks created successfully.` });

    } catch (error) {
        console.error('Bulk assign error:', error);
        res.status(500).json({ error: 'Failed to create tasks.' });
    } finally {
        if (connection) connection.release();
    }
});


app.put('/api/tasks/:id', authenticateToken, requireDB, async (req, res) => {
    let connection;
    try {
        const { id } = req.params;
        const { status, notes } = req.body;
        connection = await pool.getConnection();
        await connection.execute('UPDATE tasks SET status = ?, notes = CONCAT(IFNULL(notes,""), ?), completed_at = ? WHERE id = ?', 
            [status, `\n- ${new Date().toLocaleString()}: ${notes || 'Status updated.'}`, status === 'completed' ? new Date() : null, id]);
        res.json({ message: 'Task updated successfully' });
    } catch (error) {
        res.status(500).json({ error: 'Failed to update task' });
    } finally {
        if (connection) connection.release();
    }
});


// FOLLOW-UPS & DASHBOARD ROUTES (Largely unchanged)
app.get('/api/follow-ups', authenticateToken, requireDB, async (req, res) => {
    let connection;
    try {
        let query = `
            SELECT f.*, b.business_name, u.name as user_name
            FROM follow_ups f
            JOIN businesses b ON f.business_id = b.id
            JOIN users u ON f.user_id = u.id
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
        res.status(500).json({ error: 'Failed to fetch follow-ups' });
    } finally {
        if (connection) connection.release();
    }
});

app.get('/api/dashboard/stats', authenticateToken, requireDB, async (req, res) => {
    let connection;
    try {
        const userCondition = req.user.role !== 'admin' ? 'WHERE user_id = ?' : '';
        const userParam = req.user.role !== 'admin' ? [req.user.id] : [];
        connection = await pool.getConnection();
        
        const [[stats]] = await connection.execute(`
            SELECT
              (SELECT COUNT(*) FROM cold_calling_reports ${userCondition}) as total_visits,
              (SELECT COUNT(*) FROM telemarketing_reports ${userCondition}) as total_calls,
              (SELECT COUNT(*) FROM comprehensive_reports WHERE outcome = 'Deal Closed' ${userCondition ? 'AND user_id = ?' : ''}) as deals_closed,
              (SELECT COUNT(*) FROM comprehensive_reports WHERE DATE(activity_time) = CURDATE() ${userCondition ? 'AND user_id = ?' : ''}) as today_activity
        `, [...userParam, ...userParam, ...userParam, ...userParam]);
        
        const [weeklyActivity] = await connection.execute(`
            SELECT report_type as type, DATE(activity_time) as date, COUNT(*) as count 
            FROM comprehensive_reports 
            WHERE activity_time >= DATE_SUB(CURDATE(), INTERVAL 7 DAY) 
            ${req.user.role !== 'admin' ? 'AND user_id = ?' : ''}
            GROUP BY type, date ORDER BY date DESC
        `, userParam);

        res.json({ coldCalling: {total_visits: stats.total_visits, deals_closed: stats.deals_closed, today_visits: stats.today_activity}, telemarketing: {total_calls: stats.total_calls}, weeklyActivity });
    } catch (error) {
        console.error('Dashboard stats error:', error);
        res.status(500).json({ error: 'Failed to fetch dashboard statistics' });
    } finally {
        if (connection) connection.release();
    }
});

// Error handling & Server Start (Unchanged)
app.use((err, req, res, next) => {
    console.error('Unhandled Error:', err);
    res.status(500).json({ error: 'Internal server error' });
});
app.use((req, res) => {
    res.status(404).json({ error: 'Endpoint not found' });
});
app.listen(PORT, '0.0.0.0', () => {
    console.log(`✅ Orbyte Sales API Server running on port ${PORT}`);
});
