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

// --- Middleware Setup ---
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

// --- File Uploads & Database ---
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir, { recursive: true });
}

const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, uploadsDir),
    filename: (req, file, cb) => cb(null, `${file.fieldname}-${Date.now()}${path.extname(file.originalname)}`)
});
const upload = multer({ storage });

const JWT_SECRET = process.env.JWT_SECRET || 'your_default_secret_key';

// --- Authentication Middleware ---
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

// =============================================================================
// API ROUTES
// =============================================================================

// --- Auth Routes ---
app.post('/api/auth/login', async (req, res) => {
    let connection;
    try {
        const { email, password } = req.body;
        connection = await pool.getConnection();
        const [users] = await connection.execute('SELECT * FROM users WHERE email = ? AND status = "active"', [email]);
        if (users.length === 0 || !await bcrypt.compare(password, users[0].password)) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        const user = users[0];
        await connection.execute('UPDATE users SET last_login = NOW() WHERE id = ?', [user.id]);
        const token = jwt.sign({ id: user.id, role: user.role, name: user.name, department: user.department }, JWT_SECRET, { expiresIn: '24h' });
        res.json({ token, user: { id: user.id, name: user.name, email: user.email, role: user.role, department: user.department } });
    } catch (error) {
        console.error("Login Error:", error);
        res.status(500).json({ error: 'Internal Server Error' });
    } finally {
        if (connection) connection.release();
    }
});

// --- User Routes ---
app.get('/api/users', authenticateToken, requireAdmin, async (req, res) => {
    let connection;
    try {
        connection = await pool.getConnection();
        const [users] = await connection.execute('SELECT id, name, email, role, status, department, executive_type, phone FROM users');
        res.json(users);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch users' });
    } finally {
        if (connection) connection.release();
    }
});

app.post('/api/users', authenticateToken, requireAdmin, async (req, res) => {
    let connection;
    try {
        const { name, email, password, role, status, department, executive_type, phone } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);
        connection = await pool.getConnection();
        await connection.execute(
            'INSERT INTO users (name, email, password, role, status, department, executive_type, phone) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
            [name, email, hashedPassword, role, status || 'active', department, executive_type, phone]
        );
        res.status(201).json({ message: 'User created' });
    } catch (error) {
        if (error.code === 'ER_DUP_ENTRY') return res.status(409).json({ error: 'Email already exists' });
        res.status(500).json({ error: 'Failed to create user' });
    } finally {
        if (connection) connection.release();
    }
});

app.put('/api/users/:id', authenticateToken, requireAdmin, async (req, res) => {
    let connection;
    try {
        const { id } = req.params;
        const { name, email, role, status, department, executive_type, phone, password } = req.body;
        let query = 'UPDATE users SET name = ?, email = ?, role = ?, status = ?, department = ?, executive_type = ?, phone = ?';
        let params = [name, email, role, status, department, executive_type, phone];
        if (password) {
            query += ', password = ?';
            params.push(await bcrypt.hash(password, 10));
        }
        query += ' WHERE id = ?';
        params.push(id);
        connection = await pool.getConnection();
        await connection.execute(query, params);
        res.json({ message: 'User updated' });
    } catch (error) {
        res.status(500).json({ error: 'Failed to update user' });
    } finally {
        if (connection) connection.release();
    }
});

// --- Business Routes ---
app.get('/api/businesses', authenticateToken, async (req, res) => {
    let connection;
    try {
        const { search } = req.query;
        let query = `SELECT b.*, u.name as assigned_user_name FROM businesses b LEFT JOIN users u ON b.assigned_to = u.id`;
        let params = [];
        let conditions = [];
        if (req.user.role !== 'admin') {
            conditions.push('(b.assigned_to = ? OR b.created_by = ?)');
            params.push(req.user.id, req.user.id);
        }
        if (search) {
            conditions.push('(b.business_name LIKE ? OR b.contact_person LIKE ?)');
            params.push(`%${search}%`, `%${search}%`);
        }
        if (conditions.length) {
            query += ' WHERE ' + conditions.join(' AND ');
        }
        connection = await pool.getConnection();
        const [businesses] = await connection.execute(query, params);
        res.json(businesses);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch businesses' });
    } finally {
        if (connection) connection.release();
    }
});

app.post('/api/businesses', authenticateToken, requireAdmin, async (req, res) => {
    let connection;
    try {
        const { business_name, contact_person, status, assigned_to } = req.body;
        connection = await pool.getConnection();
        const [result] = await connection.execute(
            'INSERT INTO businesses (business_name, contact_person, status, assigned_to, created_by) VALUES (?, ?, ?, ?, ?)',
            [business_name, contact_person, status || 'New', assigned_to || null, req.user.id]
        );
        res.status(201).json({ id: result.insertId, message: 'Business created' });
    } catch (error) {
        res.status(500).json({ error: 'Failed to create business' });
    } finally {
        if (connection) connection.release();
    }
});

app.put('/api/businesses/:id', authenticateToken, requireAdmin, async (req, res) => {
    let connection;
    try {
        const { id } = req.params;
        const { business_name, contact_person, status, assigned_to } = req.body;
        connection = await pool.getConnection();
        await connection.execute(
            'UPDATE businesses SET business_name = ?, contact_person = ?, status = ?, assigned_to = ? WHERE id = ?',
            [business_name, contact_person, status, assigned_to || null, id]
        );
        res.json({ message: 'Business updated' });
    } catch (error) {
        res.status(500).json({ error: 'Failed to update business' });
    } finally {
        if (connection) connection.release();
    }
});

app.delete('/api/businesses/:id', authenticateToken, requireAdmin, async (req, res) => {
    let connection;
    try {
        connection = await pool.getConnection();
        const [result] = await connection.execute('DELETE FROM businesses WHERE id = ?', [req.params.id]);
        if (result.affectedRows === 0) {
            return res.status(404).json({ error: 'Business not found' });
        }
        res.json({ message: 'Business deleted successfully' });
    } catch (error) {
        console.error("Delete Business Error:", error);
        res.status(500).json({ error: 'Failed to delete business. It might be linked to existing records.' });
    } finally {
        if (connection) connection.release();
    }
});

// --- Report Routes ---
app.get('/api/reports', authenticateToken, async (req, res) => {
    let connection;
    try {
        const { date_from, date_to, report_type } = req.query;
        let query = 'SELECT * FROM comprehensive_reports';
        let params = [];
        let conditions = [];
        if (req.user.role !== 'admin') {
            conditions.push('user_id = ?');
            params.push(req.user.id);
        }
        if (date_from) { conditions.push('DATE(activity_time) >= ?'); params.push(date_from); }
        if (date_to) { conditions.push('DATE(activity_time) <= ?'); params.push(date_to); }
        if (report_type) { conditions.push('report_type = ?'); params.push(report_type); }
        if (conditions.length) {
            query += ' WHERE ' + conditions.join(' AND ');
        }
        query += ' ORDER BY activity_time DESC';
        connection = await pool.getConnection();
        const [reports] = await connection.execute(query, params);
        res.json({ reports });
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch reports' });
    } finally {
        if (connection) connection.release();
    }
});

app.get('/api/reports/:type/:id', authenticateToken, async (req, res) => {
    let connection;
    try {
        const { type, id } = req.params;
        const table = type === 'cold_calling' ? 'cold_calling_reports' : 'telemarketing_reports';
        connection = await pool.getConnection();
        const [reports] = await connection.execute(`SELECT r.*, u.name as user_name FROM ${table} r JOIN users u ON r.user_id = u.id WHERE r.id = ?`, [id]);
        if (reports.length === 0) return res.status(404).json({ error: 'Report not found' });
        res.json(reports[0]);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch report details' });
    } finally {
        if (connection) connection.release();
    }
});

app.post('/api/reports/cold-calling', authenticateToken, upload.single('photo_proof'), async (req, res) => {
    let connection;
    try {
        const { business_name, contact_person, visit_time, outcome, latitude, longitude } = req.body;
        connection = await pool.getConnection();
        await connection.execute(
            'INSERT INTO cold_calling_reports (user_id, business_name, contact_person, visit_time, outcome, photo_proof, latitude, longitude) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
            [req.user.id, business_name, contact_person, visit_time, outcome, req.file ? req.file.filename : null, latitude, longitude]
        );
        res.status(201).json({ message: 'Report submitted' });
    } catch (error) {
        res.status(500).json({ error: 'Failed to submit report' });
    } finally {
        if (connection) connection.release();
    }
});

app.post('/api/reports/telemarketing', authenticateToken, async (req, res) => {
    let connection;
    try {
        const { business_name, contact_person, call_time, outcome } = req.body;
        connection = await pool.getConnection();
        await connection.execute(
            'INSERT INTO telemarketing_reports (user_id, business_name, contact_person, call_time, outcome) VALUES (?, ?, ?, ?, ?)',
            [req.user.id, business_name, contact_person, call_time, outcome]
        );
        res.status(201).json({ message: 'Telemarketing report submitted' });
    } catch (error) {
        res.status(500).json({ error: 'Failed to submit report' });
    } finally {
        if (connection) connection.release();
    }
});

app.delete('/api/reports/:type/:id', authenticateToken, async (req, res) => {
    let connection;
    try {
        const { type, id } = req.params;
        const table = type === 'cold_calling' ? 'cold_calling_reports' : 'telemarketing_reports';
        connection = await pool.getConnection();
        const [reports] = await connection.execute(`SELECT * FROM ${table} WHERE id = ?`, [id]);
        if (reports.length === 0) return res.status(404).json({ error: 'Report not found' });
        if (req.user.role !== 'admin' && reports[0].user_id !== req.user.id) return res.status(403).json({ error: 'Access denied' });
        
        if (type === 'cold_calling' && reports[0].photo_proof) {
            const photoPath = path.join(__dirname, 'uploads', reports[0].photo_proof);
            if (fs.existsSync(photoPath)) fs.unlinkSync(photoPath);
        }
        await connection.execute(`DELETE FROM ${table} WHERE id = ?`, [id]);
        res.json({ message: 'Report deleted' });
    } catch (error) {
        res.status(500).json({ error: 'Failed to delete report' });
    } finally {
        if (connection) connection.release();
    }
});

// --- Task Routes ---
app.get('/api/tasks', authenticateToken, async (req, res) => {
    // This is a placeholder. You would build this out with logic similar to reports.
    res.json([]); 
});

// --- File Serving ---
app.get('/api/reports/photo/:filename', (req, res) => {
    const photoPath = path.join(__dirname, 'uploads', req.params.filename);
    if (fs.existsSync(photoPath)) res.sendFile(photoPath);
    else res.status(404).send('Not Found');
});

// --- Server Start ---
app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server is running on port ${PORT}`);
});

