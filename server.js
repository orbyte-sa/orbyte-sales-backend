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
    reconnect: true,
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
        await connection.execute('SELECT 1 as test');
        connection.release();
        
        dbConnectionStatus = 'connected';
        console.log('✅ Database connection established');
        
    } catch (error) {
        dbConnectionStatus = 'error: ' + error.message;
        console.error('❌ Database connection failed:', error.message);
        setTimeout(testConnection, 10000);
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
app.get('/api/health', async (req, res) => {
    const health = {
        status: 'OK',
        message: 'Orbyte Sales API is running',
        timestamp: new Date().toISOString(),
        environment: process.env.NODE_ENV || 'development',
        database: dbConnectionStatus
    };
    
    // Test current database connection
    try {
        const connection = await pool.getConnection();
        await connection.execute('SELECT 1 as test');
        connection.release();
        health.database = 'connected';
    } catch (error) {
        health.database = 'error: ' + error.message;
    }
    
    res.json(health);
});

// Root endpoint
app.get('/', (req, res) => {
    res.json({ 
        message: 'Orbyte Sales API Server',
        status: 'Running',
        version: '2.0.0',
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
    if (dbConnectionStatus.startsWith('error:') || dbConnectionStatus === 'unknown') {
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
        
        // Update last login
        await connection.execute(
            'UPDATE users SET last_login = NOW() WHERE email = ? AND status = "active"',
            [email]
        );

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
// USER MANAGEMENT ROUTES - FIXED
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

// =============================================================================
// FIXED USER CREATION ROUTE - Replace existing one
// =============================================================================

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

        // Validate executive_type if provided
        if (executive_type && !['indoor', 'outdoor'].includes(executive_type)) {
            return res.status(400).json({ error: 'Invalid executive type. Must be indoor or outdoor.' });
        }

        connection = await pool.getConnection();

        // Check if user already exists
        const [existingUsers] = await connection.execute(
            'SELECT id FROM users WHERE email = ?',
            [email]
        );

        if (existingUsers.length > 0) {
            return res.status(400).json({ error: 'User with this email already exists' });
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
            executive_type || null,  // Handle undefined properly
            department || 'Sales',   // Provide default
            phone || null           // Handle undefined properly
        ]);

        res.json({ 
            id: result.insertId, 
            message: 'User created successfully' 
        });

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

        // Validate role
        if (role && !['admin', 'user'].includes(role)) {
            return res.status(400).json({ error: 'Invalid role. Must be admin or user.' });
        }

        // Validate executive_type if provided
        if (executive_type && !['indoor', 'outdoor'].includes(executive_type)) {
            return res.status(400).json({ error: 'Invalid executive type. Must be indoor or outdoor.' });
        }

        connection = await pool.getConnection();

        let updateQuery = `
            UPDATE users 
            SET name = ?, email = ?, role = ?, executive_type = ?, department = ?, phone = ?, status = ?
        `;
        let params = [name, email, role, executive_type, department, phone, status];

        if (password) {
            const hashedPassword = await bcrypt.hash(password, 10);
            updateQuery += ', \`password\` = ?';
            params.push(hashedPassword);
        }

        updateQuery += ' WHERE id = ?';
        params.push(id);

        await connection.execute(updateQuery, params);
        res.json({ message: 'User updated successfully' });

    } catch (error) {
        console.error('Update user error:', error);
        res.status(500).json({ error: 'Failed to update user' });
    } finally {
        if (connection) connection.release();
    }
});

app.delete('/api/users/:id', authenticateToken, requireAdmin, requireDB, async (req, res) => {
    let connection;
    try {
        const { id } = req.params;
        
        if (parseInt(id) === req.user.id) {
            return res.status(400).json({ error: 'Cannot delete your own account' });
        }

        connection = await pool.getConnection();
        await connection.execute('UPDATE users SET status = "inactive" WHERE id = ?', [id]);
        res.json({ message: 'User deactivated successfully' });

    } catch (error) {
        console.error('Delete user error:', error);
        res.status(500).json({ error: 'Failed to delete user' });
    } finally {
        if (connection) connection.release();
    }
});

// =============================================================================
// BUSINESS MANAGEMENT ROUTES
// =============================================================================

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

        // Non-admin users only see their assigned businesses
        if (req.user.role !== 'admin') {
            conditions.push('b.assigned_to = ?');
            params.push(req.user.id);
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

// =============================================================================
// FIXED BUSINESS CREATION ROUTE - Replace existing one
// =============================================================================

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
        
        // Handle undefined/null values properly
        const [result] = await connection.execute(`
            INSERT INTO businesses 
            (business_name, contact_person, contact_position, phone, email, address, 
             city, state, postal_code, industry, business_size, priority, assigned_to, 
             created_by, notes)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `, [
            business_name,
            contact_person || null,
            contact_position || null,
            phone || null,
            email || null,
            address || null,
            city || null,
            state || null,
            postal_code || null,
            industry || null,
            business_size || 'Small',
            priority || 'Medium',
            assigned_to || null,  // This was causing the undefined error
            req.user.id,
            notes || null
        ]);

        res.json({ 
            id: result.insertId, 
            message: 'Business created successfully' 
        });

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

        // Check permissions
        if (req.user.role !== 'admin') {
            const [business] = await connection.execute(
                'SELECT assigned_to FROM businesses WHERE id = ?', [id]
            );
            if (business.length === 0 || business[0].assigned_to !== req.user.id) {
                return res.status(403).json({ error: 'Access denied' });
            }
        }

        await connection.execute(`
            UPDATE businesses 
            SET business_name = ?, contact_person = ?, contact_position = ?, phone = ?, 
                email = ?, address = ?, city = ?, state = ?, postal_code = ?, 
                industry = ?, business_size = ?, priority = ?, assigned_to = ?, 
                status = ?, notes = ?
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

// Bulk upload businesses from CSV
app.post('/api/businesses/bulk-upload', authenticateToken, requireAdmin, requireDB, upload.single('csv_file'), async (req, res) => {
    let connection;
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'CSV file is required' });
        }

        const csvData = fs.readFileSync(req.file.path, 'utf8');
        const lines = csvData.split('\n').filter(line => line.trim());
        
        if (lines.length < 2) {
            return res.status(400).json({ error: 'CSV file must contain headers and at least one data row' });
        }

        const headers = lines[0].split(',').map(h => h.trim().replace(/"/g, ''));
        const businesses = [];

        for (let i = 1; i < lines.length; i++) {
            const values = lines[i].split(',').map(v => v.trim().replace(/"/g, ''));
            if (values.length >= headers.length && values[0]) {
                const business = {};
                headers.forEach((header, index) => {
                    business[header.toLowerCase().replace(' ', '_')] = values[index] || null;
                });
                businesses.push(business);
            }
        }

        connection = await pool.getConnection();
        let successCount = 0;
        let errorCount = 0;

        for (const business of businesses) {
            try {
                await connection.execute(`
                    INSERT INTO businesses 
                    (business_name, contact_person, contact_position, phone, email, 
                     address, city, state, postal_code, industry, business_size, 
                     priority, created_by, status)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'New')
                `, [
                    business.business_name,
                    business.contact_person,
                    business.contact_position,
                    business.phone,
                    business.email,
                    business.address,
                    business.city,
                    business.state,
                    business.postal_code,
                    business.industry,
                    business.business_size || 'Small',
                    business.priority || 'Medium',
                    req.user.id
                ]);
                successCount++;
            } catch (err) {
                console.error('Error inserting business:', err);
                errorCount++;
            }
        }

        // Clean up uploaded file
        fs.unlinkSync(req.file.path);

        res.json({
            message: `Bulk upload completed`,
            success_count: successCount,
            error_count: errorCount,
            total_processed: businesses.length
        });

    } catch (error) {
        console.error('Bulk upload error:', error);
        res.status(500).json({ error: 'Failed to process bulk upload' });
    } finally {
        if (connection) connection.release();
    }
});

// =============================================================================
// GOALS AND TARGETS ROUTES
// =============================================================================

app.get('/api/goals', authenticateToken, requireDB, async (req, res) => {
    let connection;
    try {
        const { user_id } = req.query;
        let conditions = ['g.status = "active"'];
        let params = [];

        // Non-admin users can only see their own goals
        if (req.user.role !== 'admin') {
            conditions.push('g.user_id = ?');
            params.push(req.user.id);
        } else if (user_id) {
            conditions.push('g.user_id = ?');
            params.push(user_id);
        }

        const whereClause = 'WHERE ' + conditions.join(' AND ');

        connection = await pool.getConnection();
        const [goals] = await connection.execute(`
            SELECT g.*, u.name as user_name
            FROM goals g
            JOIN users u ON g.user_id = u.id
            ${whereClause}
            ORDER BY g.created_at DESC
        `, params);

        res.json(goals);

    } catch (error) {
        console.error('Get goals error:', error);
        res.status(500).json({ error: 'Failed to fetch goals' });
    } finally {
        if (connection) connection.release();
    }
});

app.post('/api/goals', authenticateToken, requireDB, async (req, res) => {
    let connection;
    try {
        const { user_id, goal_type, activity_type, target_value, start_date, end_date } = req.body;

        if (!goal_type || !activity_type || !target_value || !start_date || !end_date) {
            return res.status(400).json({ error: 'All fields are required' });
        }

        // Only admin can set goals for other users
        const targetUserId = req.user.role === 'admin' && user_id ? user_id : req.user.id;

        connection = await pool.getConnection();
        const [result] = await connection.execute(`
            INSERT INTO goals (user_id, goal_type, activity_type, target_value, start_date, end_date)
            VALUES (?, ?, ?, ?, ?, ?)
        `, [targetUserId, goal_type, activity_type, target_value, start_date, end_date]);

        res.json({ 
            id: result.insertId, 
            message: 'Goal created successfully' 
        });

    } catch (error) {
        console.error('Create goal error:', error);
        res.status(500).json({ error: 'Failed to create goal' });
    } finally {
        if (connection) connection.release();
    }
});

app.put('/api/goals/:id', authenticateToken, requireDB, async (req, res) => {
    let connection;
    try {
        const { id } = req.params;
        const { goal_type, activity_type, target_value, start_date, end_date, status } = req.body;

        connection = await pool.getConnection();

        // Check permissions
        if (req.user.role !== 'admin') {
            const [goal] = await connection.execute(
                'SELECT user_id FROM goals WHERE id = ?', [id]
            );
            if (goal.length === 0 || goal[0].user_id !== req.user.id) {
                return res.status(403).json({ error: 'Access denied' });
            }
        }

        await connection.execute(`
            UPDATE goals 
            SET goal_type = ?, activity_type = ?, target_value = ?, start_date = ?, end_date = ?, status = ?
            WHERE id = ?
        `, [goal_type, activity_type, target_value, start_date, end_date, status, id]);

        res.json({ message: 'Goal updated successfully' });

    } catch (error) {
        console.error('Update goal error:', error);
        res.status(500).json({ error: 'Failed to update goal' });
    } finally {
        if (connection) connection.release();
    }
});

// =============================================================================
// TASKS AND ASSIGNMENTS ROUTES
// =============================================================================

app.get('/api/tasks', authenticateToken, requireDB, async (req, res) => {
    let connection;
    try {
        const { status, assigned_to } = req.query;
        let conditions = [];
        let params = [];

        if (status) {
            conditions.push('t.status = ?');
            params.push(status);
        }

        // Non-admin users only see their assigned tasks
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
            SELECT t.*, 
                   assigned_user.name as assigned_user_name,
                   assigner.name as assigned_by_name,
                   b.business_name
            FROM tasks t
            LEFT JOIN users assigned_user ON t.assigned_to = assigned_user.id
            LEFT JOIN users assigner ON t.assigned_by = assigner.id
            LEFT JOIN businesses b ON t.business_id = b.id
            ${whereClause}
            ORDER BY t.due_date ASC, t.priority DESC
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
        const { title, description, assigned_to, business_id, task_type, priority, due_date } = req.body;

        if (!title || !assigned_to || !task_type) {
            return res.status(400).json({ error: 'Title, assigned user, and task type are required' });
        }

        connection = await pool.getConnection();
        const [result] = await connection.execute(`
            INSERT INTO tasks 
            (title, description, assigned_to, assigned_by, business_id, task_type, priority, due_date)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `, [title, description, assigned_to, req.user.id, business_id, task_type, priority, due_date]);

        // Create notification for assigned user
        await connection.execute(`
            INSERT INTO notifications (user_id, title, message, type, action_url)
            VALUES (?, ?, ?, 'task_due', ?)
        `, [
            assigned_to,
            'New Task Assigned',
            `You have been assigned a new task: ${title}`,
            `/tasks/${result.insertId}`
        ]);

        res.json({ 
            id: result.insertId, 
            message: 'Task created successfully' 
        });

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
        const { status, notes, title, description, priority, due_date } = req.body;

        connection = await pool.getConnection();

        // Check if user can update this task
        const [tasks] = await connection.execute(
            'SELECT assigned_to, assigned_by FROM tasks WHERE id = ?', [id]
        );

        if (tasks.length === 0) {
            return res.status(404).json({ error: 'Task not found' });
        }

        const task = tasks[0];
        if (req.user.role !== 'admin' && task.assigned_to !== req.user.id && task.assigned_by !== req.user.id) {
            return res.status(403).json({ error: 'Access denied' });
        }

        const completedAt = status === 'completed' ? 'NOW()' : 'NULL';
        
        // Build dynamic update query based on provided fields
        let updateFields = [];
        let params = [];
        
        if (status !== undefined) {
            updateFields.push('status = ?');
            params.push(status);
        }
        if (notes !== undefined) {
            updateFields.push('notes = ?');
            params.push(notes);
        }
        if (title !== undefined) {
            updateFields.push('title = ?');
            params.push(title);
        }
        if (description !== undefined) {
            updateFields.push('description = ?');
            params.push(description);
        }
        if (priority !== undefined) {
            updateFields.push('priority = ?');
            params.push(priority);
        }
        if (due_date !== undefined) {
            updateFields.push('due_date = ?');
            params.push(due_date);
        }
        
        if (status === 'completed') {
            updateFields.push('completed_at = NOW()');
        }
        
        params.push(id);

        await connection.execute(`
            UPDATE tasks 
            SET ${updateFields.join(', ')}
            WHERE id = ?
        `, params);

        res.json({ message: 'Task updated successfully' });

    } catch (error) {
        console.error('Update task error:', error);
        res.status(500).json({ error: 'Failed to update task' });
    } finally {
        if (connection) connection.release();
    }
});

// =============================================================================
// NOTIFICATIONS ROUTES
// =============================================================================

app.get('/api/notifications', authenticateToken, requireDB, async (req, res) => {
    let connection;
    try {
        connection = await pool.getConnection();
        const [notifications] = await connection.execute(`
            SELECT * FROM notifications 
            WHERE user_id = ? AND (expires_at IS NULL OR expires_at > NOW())
            ORDER BY created_at DESC 
            LIMIT 50
        `, [req.user.id]);

        res.json(notifications);

    } catch (error) {
        console.error('Get notifications error:', error);
        res.status(500).json({ error: 'Failed to fetch notifications' });
    } finally {
        if (connection) connection.release();
    }
});

app.put('/api/notifications/:id/read', authenticateToken, requireDB, async (req, res) => {
    let connection;
    try {
        const { id } = req.params;

        connection = await pool.getConnection();
        await connection.execute(
            'UPDATE notifications SET is_read = TRUE WHERE id = ? AND user_id = ?',
            [id, req.user.id]
        );

        res.json({ message: 'Notification marked as read' });

    } catch (error) {
        console.error('Mark notification read error:', error);
        res.status(500).json({ error: 'Failed to mark notification as read' });
    } finally {
        if (connection) connection.release();
    }
});

// =============================================================================
// ENHANCED REPORT ROUTES - FIXED
// =============================================================================

app.post('/api/reports/cold-calling', authenticateToken, requireDB, upload.single('photo_proof'), async (req, res) => {
    let connection;
    try {
        const {
            business_name, contact_person, contact_position, visit_time, outcome, notes,
            latitude, longitude, business_id, follow_up_required, follow_up_date
        } = req.body;

        if (!business_name || !contact_person || !contact_position || !visit_time || !outcome) {
            return res.status(400).json({ error: 'All required fields must be filled' });
        }

        // Convert datetime-local to MySQL datetime format
        const visitDateTime = new Date(visit_time).toISOString().slice(0, 19).replace('T', ' ');
        const photo_path = req.file ? req.file.filename : null;

        connection = await pool.getConnection();
        
        // Start transaction
        await connection.execute('START TRANSACTION');

        // Handle business_id validation - if provided, check if it exists
        let validBusinessId = null;
        if (business_id && business_id !== '' && business_id !== 'null') {
            const [businessCheck] = await connection.execute(
                'SELECT id FROM businesses WHERE id = ?', 
                [business_id]
            );
            if (businessCheck.length > 0) {
                validBusinessId = business_id;
            }
        }

        const [result] = await connection.execute(`
            INSERT INTO cold_calling_reports 
            (user_id, business_name, contact_person, contact_position, visit_time, 
             photo_proof, outcome, notes, latitude, longitude, business_id, 
             follow_up_required, follow_up_date, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())
        `, [
            req.user.id, 
            business_name, 
            contact_person, 
            contact_position, 
            visitDateTime, 
            photo_path, 
            outcome, 
            notes || null, 
            latitude || null, 
            longitude || null, 
            validBusinessId,  // This fixes the foreign key constraint error
            follow_up_required === 'true', 
            follow_up_date || null
        ]);

        // Add to business interactions only if we have a valid business_id
        if (validBusinessId) {
            await connection.execute(`
                INSERT INTO business_interactions 
                (business_id, user_id, interaction_type, outcome, notes, interaction_date)
                VALUES (?, ?, 'cold_call', ?, ?, ?)
            `, [validBusinessId, req.user.id, outcome, notes || null, visitDateTime]);

            // Update business status if deal closed
            if (outcome === 'Deal Closed') {
                await connection.execute(
                    'UPDATE businesses SET status = "Deal Closed" WHERE id = ?',
                    [validBusinessId]
                );
            }
        }

        // Create follow-up if required and we have a valid business_id
        if (follow_up_required === 'true' && follow_up_date && validBusinessId) {
            await connection.execute(`
                INSERT INTO follow_ups 
                (business_id, user_id, report_id, report_type, follow_up_type, scheduled_date, notes)
                VALUES (?, ?, ?, 'cold_calling', 'call', ?, 'Follow-up from cold calling visit')
            `, [validBusinessId, req.user.id, result.insertId, follow_up_date]);
        }

        // Update goals progress
        await updateGoalProgress(connection, req.user.id, 'cold_calling', outcome);

        await connection.execute('COMMIT');

        res.json({ 
            id: result.insertId, 
            message: 'Cold calling report submitted successfully' 
        });

    } catch (error) {
        if (connection) await connection.execute('ROLLBACK');
        console.error('Submit cold calling report error:', error);
        res.status(500).json({ error: 'Failed to submit report' });
    } finally {
        if (connection) connection.release();
    }
});


// =============================================================================
// FIXED TELEMARKETING REPORT ROUTE - Replace existing one
// =============================================================================

app.post('/api/reports/telemarketing', authenticateToken, requireDB, async (req, res) => {
    let connection;
    try {
        const {
            business_name, contact_person, contact_position, call_time, outcome, notes,
            business_id, follow_up_required, follow_up_date
        } = req.body;

        if (!business_name || !contact_person || !contact_position || !call_time || !outcome) {
            return res.status(400).json({ error: 'All required fields must be filled' });
        }

        // Convert datetime-local to MySQL datetime format
        const callDateTime = new Date(call_time).toISOString().slice(0, 19).replace('T', ' ');

        connection = await pool.getConnection();
        
        // Start transaction
        await connection.execute('START TRANSACTION');

        // Handle business_id validation - if provided, check if it exists
        let validBusinessId = null;
        if (business_id && business_id !== '' && business_id !== 'null') {
            const [businessCheck] = await connection.execute(
                'SELECT id FROM businesses WHERE id = ?', 
                [business_id]
            );
            if (businessCheck.length > 0) {
                validBusinessId = business_id;
            }
        }

        const [result] = await connection.execute(`
            INSERT INTO telemarketing_reports 
            (user_id, business_name, contact_person, contact_position, call_time, 
             outcome, notes, business_id, follow_up_required, follow_up_date, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())
        `, [
            req.user.id, 
            business_name, 
            contact_person, 
            contact_position, 
            callDateTime, 
            outcome, 
            notes || null, 
            validBusinessId,  // This fixes the foreign key constraint error
            follow_up_required === 'true', 
            follow_up_date || null
        ]);

        // Add to business interactions only if we have a valid business_id
        if (validBusinessId) {
            await connection.execute(`
                INSERT INTO business_interactions 
                (business_id, user_id, interaction_type, outcome, notes, interaction_date)
                VALUES (?, ?, 'telemarketing', ?, ?, ?)
            `, [validBusinessId, req.user.id, outcome, notes || null, callDateTime]);

            // Update business status if deal closed
            if (outcome === 'Deal Closed') {
                await connection.execute(
                    'UPDATE businesses SET status = "Deal Closed" WHERE id = ?',
                    [validBusinessId]
                );
            }
        }

        // Create follow-up if required and we have a valid business_id
        if (follow_up_required === 'true' && follow_up_date && validBusinessId) {
            await connection.execute(`
                INSERT INTO follow_ups 
                (business_id, user_id, report_id, report_type, follow_up_type, scheduled_date, notes)
                VALUES (?, ?, ?, 'telemarketing', 'call', ?, 'Follow-up from telemarketing call')
            `, [validBusinessId, req.user.id, result.insertId, follow_up_date]);
        }

        // Update goals progress
        await updateGoalProgress(connection, req.user.id, 'telemarketing', outcome);

        await connection.execute('COMMIT');

        res.json({ 
            id: result.insertId, 
            message: 'Telemarketing report submitted successfully' 
        });

    } catch (error) {
        if (connection) await connection.execute('ROLLBACK');
        console.error('Submit telemarketing report error:', error);
        res.status(500).json({ error: 'Failed to submit report' });
    } finally {
        if (connection) connection.release();
    }
});

// Enhanced Get reports with advanced filtering
app.get('/api/reports', authenticateToken, requireDB, async (req, res) => {
    let connection;
    try {
        const { 
            date_from, date_to, outcome, business_name, contact_person, 
            report_type, user_id, business_id, page = 1, limit = 50
        } = req.query;
        
        let conditions = [];
        let params = [];

        // If not admin, only show user's own reports
        if (req.user.role !== 'admin') {
            conditions.push('user_id = ?');
            params.push(req.user.id);
        } else if (user_id) {
            conditions.push('user_id = ?');
            params.push(user_id);
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
        if (contact_person) {
            conditions.push('contact_person LIKE ?');
            params.push(`%${contact_person}%`);
        }
        if (business_id) {
            conditions.push('business_id = ?');
            params.push(business_id);
        }

        const whereClause = conditions.length > 0 ? 'WHERE ' + conditions.join(' AND ') : '';
        const offset = (page - 1) * limit;

        connection = await pool.getConnection();

        let query = `
            SELECT * FROM comprehensive_reports
            ${whereClause}
        `;

        if (report_type) {
            if (whereClause) {
                query += ' AND report_type = ?';
            } else {
                query += ' WHERE report_type = ?';
            }
            params.push(report_type);
        }

        query += `
            ORDER BY created_at DESC
            LIMIT ? OFFSET ?
        `;
        params.push(parseInt(limit), offset);

        const [reports] = await connection.execute(query, params);

        // Get total count for pagination
        let countQuery = `
            SELECT COUNT(*) as total FROM comprehensive_reports
            ${whereClause}
        `;
        let countParams = [...params.slice(0, -2)]; // Remove limit and offset

        if (report_type) {
            if (whereClause) {
                countQuery += ' AND report_type = ?';
            } else {
                countQuery += ' WHERE report_type = ?';
            }
            countParams.push(report_type);
        }

        const [countResult] = await connection.execute(countQuery, countParams);
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

// =============================================================================
// FOLLOW-UP MANAGEMENT ROUTES
// =============================================================================

app.get('/api/follow-ups', authenticateToken, requireDB, async (req, res) => {
    let connection;
    try {
        const { status, date_from, date_to } = req.query;
        let conditions = [];
        let params = [];

        // Non-admin users only see their own follow-ups
        if (req.user.role !== 'admin') {
            conditions.push('f.user_id = ?');
            params.push(req.user.id);
        }

        if (status) {
            conditions.push('f.status = ?');
            params.push(status);
        }
        if (date_from) {
            conditions.push('DATE(f.scheduled_date) >= ?');
            params.push(date_from);
        }
        if (date_to) {
            conditions.push('DATE(f.scheduled_date) <= ?');
            params.push(date_to);
        }

        const whereClause = conditions.length > 0 ? 'WHERE ' + conditions.join(' AND ') : '';

        connection = await pool.getConnection();
        const [followUps] = await connection.execute(`
            SELECT f.*, 
                   b.business_name,
                   u.name as user_name
            FROM follow_ups f
            LEFT JOIN businesses b ON f.business_id = b.id
            LEFT JOIN users u ON f.user_id = u.id
            ${whereClause}
            ORDER BY f.scheduled_date ASC
        `, params);

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

        // Check permissions
        if (req.user.role !== 'admin') {
            const [followUp] = await connection.execute(
                'SELECT user_id FROM follow_ups WHERE id = ?', [id]
            );
            if (followUp.length === 0 || followUp[0].user_id !== req.user.id) {
                return res.status(403).json({ error: 'Access denied' });
            }
        }

        const completedAt = status === 'completed' ? 'NOW()' : null;

        await connection.execute(`
            UPDATE follow_ups 
            SET status = ?, outcome = ?, notes = ?, scheduled_date = ?, completed_at = ?
            WHERE id = ?
        `, [status, outcome, notes, scheduled_date, completedAt, id]);

        res.json({ message: 'Follow-up updated successfully' });

    } catch (error) {
        console.error('Update follow-up error:', error);
        res.status(500).json({ error: 'Failed to update follow-up' });
    } finally {
        if (connection) connection.release();
    }
});

// =============================================================================
// TEAM MESSAGES AND ANNOUNCEMENTS
// =============================================================================

app.get('/api/team-messages', authenticateToken, requireDB, async (req, res) => {
    let connection;
    try {
        connection = await pool.getConnection();
        const [messages] = await connection.execute(`
            SELECT tm.*, u.name as created_by_name
            FROM team_messages tm
            LEFT JOIN users u ON tm.created_by = u.id
            WHERE tm.is_active = TRUE 
              AND (tm.expires_at IS NULL OR tm.expires_at > NOW())
              AND (tm.target_role = 'all' OR tm.target_role = ?)
              AND (tm.target_department IS NULL OR tm.target_department = ? OR tm.target_department = 'all')
            ORDER BY tm.priority DESC, tm.created_at DESC
        `, [req.user.role, req.user.department]);

        res.json(messages);

    } catch (error) {
        console.error('Get team messages error:', error);
        res.status(500).json({ error: 'Failed to fetch team messages' });
    } finally {
        if (connection) connection.release();
    }
});

app.post('/api/team-messages', authenticateToken, requireAdmin, requireDB, async (req, res) => {
    let connection;
    try {
        const { title, message, target_role, target_department, priority, expires_at } = req.body;

        if (!title || !message) {
            return res.status(400).json({ error: 'Title and message are required' });
        }

        connection = await pool.getConnection();
        const [result] = await connection.execute(`
            INSERT INTO team_messages 
            (title, message, created_by, target_role, target_department, priority, expires_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        `, [title, message, req.user.id, target_role, target_department, priority, expires_at]);

        res.json({ 
            id: result.insertId, 
            message: 'Team message created successfully' 
        });

    } catch (error) {
        console.error('Create team message error:', error);
        res.status(500).json({ error: 'Failed to create team message' });
    } finally {
        if (connection) connection.release();
    }
});

// =============================================================================
// ENHANCED DASHBOARD ROUTES
// =============================================================================

app.get('/api/dashboard/stats', authenticateToken, requireDB, async (req, res) => {
    let connection;
    try {
        const userCondition = req.user.role !== 'admin' ? 'WHERE user_id = ?' : '';
        const userParam = req.user.role !== 'admin' ? [req.user.id] : [];

        connection = await pool.getConnection();

        // Get comprehensive statistics
        const [coldStats] = await connection.execute(`
            SELECT 
                COUNT(*) as total_visits,
                SUM(CASE WHEN outcome = 'Deal Closed' THEN 1 ELSE 0 END) as deals_closed,
                SUM(CASE WHEN DATE(created_at) = CURDATE() THEN 1 ELSE 0 END) as today_visits
            FROM cold_calling_reports 
            ${userCondition}
        `, userParam);

        const [teleStats] = await connection.execute(`
            SELECT 
                COUNT(*) as total_calls,
                SUM(CASE WHEN outcome = 'Deal Closed' THEN 1 ELSE 0 END) as deals_closed,
                SUM(CASE WHEN DATE(created_at) = CURDATE() THEN 1 ELSE 0 END) as today_calls
            FROM telemarketing_reports 
            ${userCondition}
        `, userParam);
        
        // Query for weekly activity chart
        const [weeklyActivity] = await connection.execute(`
            (SELECT 'cold_calling' as type, DATE(created_at) as date, COUNT(*) as count 
             FROM cold_calling_reports 
             ${userCondition ? 'WHERE created_at >= DATE_SUB(CURDATE(), INTERVAL 7 DAY) AND user_id = ?' : 'WHERE created_at >= DATE_SUB(CURDATE(), INTERVAL 7 DAY)'}
             GROUP BY DATE(created_at))
            UNION ALL
            (SELECT 'telemarketing' as type, DATE(created_at) as date, COUNT(*) as count 
             FROM telemarketing_reports 
             ${userCondition ? 'WHERE created_at >= DATE_SUB(CURDATE(), INTERVAL 7 DAY) AND user_id = ?' : 'WHERE created_at >= DATE_SUB(CURDATE(), INTERVAL 7 DAY)'}
             GROUP BY DATE(created_at))
            ORDER BY date DESC
        `, [...userParam, ...userParam]);

        // Get goals progress
        const [goalsProgress] = await connection.execute(`
            SELECT g.*, 
                   CASE 
                       WHEN g.goal_type = 'daily' THEN 
                           CASE WHEN g.activity_type = 'cold_calling' THEN
                               (SELECT COUNT(*) FROM cold_calling_reports WHERE user_id = g.user_id AND DATE(created_at) = CURDATE())
                           WHEN g.activity_type = 'telemarketing' THEN
                               (SELECT COUNT(*) FROM telemarketing_reports WHERE user_id = g.user_id AND DATE(created_at) = CURDATE())
                           WHEN g.activity_type = 'deals' THEN
                               (SELECT COUNT(*) FROM comprehensive_reports WHERE user_id = g.user_id AND outcome = 'Deal Closed' AND DATE(created_at) = CURDATE())
                           ELSE 0
                       END
                       WHEN g.goal_type = 'weekly' THEN
                           CASE WHEN g.activity_type = 'cold_calling' THEN
                               (SELECT COUNT(*) FROM cold_calling_reports WHERE user_id = g.user_id AND WEEK(created_at) = WEEK(CURDATE()))
                           WHEN g.activity_type = 'telemarketing' THEN
                               (SELECT COUNT(*) FROM telemarketing_reports WHERE user_id = g.user_id AND WEEK(created_at) = WEEK(CURDATE()))
                           WHEN g.activity_type = 'deals' THEN
                               (SELECT COUNT(*) FROM comprehensive_reports WHERE user_id = g.user_id AND outcome = 'Deal Closed' AND WEEK(created_at) = WEEK(CURDATE()))
                           ELSE 0
                       END
                   END as current_progress
            FROM goals g
            WHERE g.status = 'active' 
              AND CURDATE() BETWEEN g.start_date AND g.end_date
              ${req.user.role !== 'admin' ? 'AND g.user_id = ?' : ''}
        `, req.user.role !== 'admin' ? [req.user.id] : []);

        // Get pending tasks count
        const [taskStats] = await connection.execute(`
            SELECT 
                COUNT(*) as total_tasks,
                SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) as pending_tasks,
                SUM(CASE WHEN status = 'in_progress' THEN 1 ELSE 0 END) as in_progress_tasks,
                SUM(CASE WHEN DATE(due_date) = CURDATE() THEN 1 ELSE 0 END) as due_today
            FROM tasks 
            WHERE assigned_to = ?
        `, [req.user.id]);

        // Get follow-ups count
        const [followUpStats] = await connection.execute(`
            SELECT 
                COUNT(*) as total_followups,
                SUM(CASE WHEN status = 'scheduled' THEN 1 ELSE 0 END) as scheduled_followups,
                SUM(CASE WHEN DATE(scheduled_date) = CURDATE() THEN 1 ELSE 0 END) as due_today
            FROM follow_ups 
            WHERE user_id = ?
        `, [req.user.id]);

        res.json({
            coldCalling: coldStats[0] || { total_visits: 0, deals_closed: 0, today_visits: 0 },
            telemarketing: teleStats[0] || { total_calls: 0, deals_closed: 0, today_calls: 0 },
            goals: goalsProgress,
            tasks: taskStats[0] || { total_tasks: 0, pending_tasks: 0, in_progress_tasks: 0, due_today: 0 },
            followUps: followUpStats[0] || { total_followups: 0, scheduled_followups: 0, due_today: 0 },
            weeklyActivity: weeklyActivity
        });

    } catch (error) {
        console.error('Dashboard stats error:', error);
        res.status(500).json({ error: 'Failed to fetch dashboard statistics' });
    } finally {
        if (connection) connection.release();
    }
});

// =============================================================================
// UTILITY FUNCTIONS
// =============================================================================

async function updateGoalProgress(connection, userId, activityType, outcome) {
    try {
        // Update daily goals
        await connection.execute(`
            UPDATE goals 
            SET current_value = (
                SELECT COUNT(*) 
                FROM ${activityType === 'cold_calling' ? 'cold_calling_reports' : 'telemarketing_reports'} 
                WHERE user_id = ? AND DATE(created_at) = CURDATE()
            )
            WHERE user_id = ? 
              AND goal_type = 'daily' 
              AND activity_type = ? 
              AND status = 'active'
              AND CURDATE() BETWEEN start_date AND end_date
        `, [userId, userId, activityType]);

        // Update weekly goals
        await connection.execute(`
            UPDATE goals 
            SET current_value = (
                SELECT COUNT(*) 
                FROM ${activityType === 'cold_calling' ? 'cold_calling_reports' : 'telemarketing_reports'} 
                WHERE user_id = ? AND WEEK(created_at) = WEEK(CURDATE())
            )
            WHERE user_id = ? 
              AND goal_type = 'weekly' 
              AND activity_type = ? 
              AND status = 'active'
              AND CURDATE() BETWEEN start_date AND end_date
        `, [userId, userId, activityType]);

        // Update deal goals if applicable
        if (outcome === 'Deal Closed') {
            await connection.execute(`
                UPDATE goals 
                SET current_value = current_value + 1
                WHERE user_id = ? 
                  AND activity_type = 'deals' 
                  AND status = 'active'
                  AND CURDATE() BETWEEN start_date AND end_date
            `, [userId]);
        }

    } catch (error) {
        console.error('Error updating goal progress:', error);
    }
}

// Delete report (enhanced with business interaction cleanup)
app.delete('/api/reports/:type/:id', authenticateToken, requireDB, async (req, res) => {
    let connection;
    try {
        const { type, id } = req.params;
        const table = type === 'cold_calling' ? 'cold_calling_reports' : 'telemarketing_reports';

        connection = await pool.getConnection();

        // Start transaction
        await connection.execute('START TRANSACTION');

        // Check if report exists and belongs to user (or user is admin)
        const [reports] = await connection.execute(
            `SELECT * FROM ${table} WHERE id = ? ${req.user.role !== 'admin' ? 'AND user_id = ?' : ''}`,
            req.user.role !== 'admin' ? [id, req.user.id] : [id]
        );

        if (reports.length === 0) {
            await connection.execute('ROLLBACK');
            return res.status(404).json({ error: 'Report not found' });
        }

        const report = reports[0];

        // Check if report was created today (for non-admin users)
        if (req.user.role !== 'admin') {
            const today = new Date().toISOString().split('T')[0];
            const reportDate = new Date(report.created_at).toISOString().split('T')[0];
            
            if (today !== reportDate) {
                await connection.execute('ROLLBACK');
                return res.status(403).json({ error: 'Can only delete reports from today' });
            }
        }

        // Delete related records
        await connection.execute('DELETE FROM follow_ups WHERE report_id = ? AND report_type = ?', [id, type]);
        await connection.execute('DELETE FROM business_interactions WHERE user_id = ? AND interaction_date = ?', [report.user_id, report.visit_time || report.call_time]);

        // Delete photo file if exists
        if (type === 'cold_calling' && report.photo_proof) {
            const photoPath = path.join('uploads', report.photo_proof);
            if (fs.existsSync(photoPath)) {
                fs.unlinkSync(photoPath);
            }
        }

        await connection.execute(`DELETE FROM ${table} WHERE id = ?`, [id]);

        // Update goal progress
        await updateGoalProgress(connection, report.user_id, type, report.outcome);

        await connection.execute('COMMIT');

        res.json({ message: 'Report deleted successfully' });

    } catch (error) {
        if (connection) await connection.execute('ROLLBACK');
        console.error('Delete report error:', error);
        res.status(500).json({ error: 'Failed to delete report' });
    } finally {
        if (connection) connection.release();
    }
});

// Enhanced CSV export with new data
app.get('/api/reports/export', authenticateToken, requireAdmin, requireDB, async (req, res) => {
    let connection;
    try {
        connection = await pool.getConnection();

        const [allReports] = await connection.execute(`
            SELECT 
                report_type,
                user_name as executive_name,
                department,
                business_name,
                contact_person,
                contact_position,
                activity_time,
                outcome,
                notes,
                created_at as submission_time,
                latitude,
                longitude,
                photo_proof,
                follow_up_required,
                follow_up_date
            FROM comprehensive_reports
            ORDER BY created_at DESC
        `);

        if (allReports.length === 0) {
            return res.status(404).json({ error: 'No reports found' });
        }

        const csvHeaders = [
            'Report Type', 'Executive Name', 'Department', 'Business Name', 'Contact Person', 
            'Contact Position', 'Activity Time', 'Outcome', 'Notes', 
            'Submission Time', 'Latitude', 'Longitude', 'Photo Proof',
            'Follow-up Required', 'Follow-up Date'
        ].join(',');

        const csvRows = allReports.map(row => [
            `"${row.report_type}"`,
            `"${row.executive_name}"`,
            `"${row.department || ''}"`,
            `"${row.business_name}"`,
            `"${row.contact_person}"`,
            `"${row.contact_position}"`,
            `"${row.activity_time}"`,
            `"${row.outcome}"`,
            `"${row.notes || ''}"`,
            `"${row.submission_time}"`,
            `"${row.latitude || ''}"`,
            `"${row.longitude || ''}"`,
            `"${row.photo_proof || ''}"`,
            `"${row.follow_up_required ? 'Yes' : 'No'}"`,
            `"${row.follow_up_date || ''}"`
        ].join(',')).join('\n');

        const csv = csvHeaders + '\n' + csvRows;

        res.setHeader('Content-Type', 'text/csv');
        res.setHeader('Content-Disposition', `attachment; filename="orbyte_sales_reports_${new Date().toISOString().split('T')[0]}.csv"`);
        res.send(csv);

    } catch (error) {
        console.error('Export reports error:', error);
        res.status(500).json({ error: 'Failed to export reports' });
    } finally {
        if (connection) connection.release();
    }
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error('Error:', err);
    res.status(500).json({ error: 'Internal server error' });
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({ error: 'Endpoint not found' });
});

// Handle graceful shutdown
process.on('SIGTERM', async () => {
    console.log('SIGTERM received, shutting down gracefully');
    await pool.end();
    process.exit(0);
});

process.on('SIGINT', async () => {
    console.log('SIGINT received, shutting down gracefully');
    await pool.end();
    process.exit(0);
});

// Start server
app.listen(PORT, '0.0.0.0', () => {
    console.log(`✅ Orbyte Sales API Server running on port ${PORT}`);
    console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
});

// =============================================================================
// AUTO-NOTIFICATION SYSTEM (Background Tasks)
// =============================================================================

// Function to check and send goal reminders
async function checkGoalReminders() {
    let connection;
    try {
        connection = await pool.getConnection();
        
        // Check for users who haven't met their daily goals
        const [usersWithDailyGoals] = await connection.execute(`
            SELECT g.user_id, g.activity_type, g.target_value, u.name, u.email,
                   COALESCE(current_progress.count, 0) as current_progress
            FROM goals g
            JOIN users u ON g.user_id = u.id
            LEFT JOIN (
                SELECT user_id, 
                       COUNT(*) as count,
                       'cold_calling' as activity_type
                FROM cold_calling_reports 
                WHERE DATE(created_at) = CURDATE()
                GROUP BY user_id
                UNION ALL
                SELECT user_id, 
                       COUNT(*) as count,
                       'telemarketing' as activity_type
                FROM telemarketing_reports 
                WHERE DATE(created_at) = CURDATE()
                GROUP BY user_id
            ) current_progress ON g.user_id = current_progress.user_id 
                              AND g.activity_type = current_progress.activity_type
            WHERE g.goal_type = 'daily' 
              AND g.status = 'active'
              AND CURDATE() BETWEEN g.start_date AND g.end_date
              AND HOUR(NOW()) = 16  -- Send reminder at 4 PM
              AND COALESCE(current_progress.count, 0) < g.target_value
        `);

        for (const user of usersWithDailyGoals) {
            await connection.execute(`
                INSERT INTO notifications (user_id, title, message, type, priority)
                VALUES (?, ?, ?, 'goal_reminder', 'medium')
            `, [
                user.user_id,
                'Daily Goal Reminder',
                `You're ${user.target_value - user.current_progress} ${user.activity_type.replace('_', ' ')} activities away from your daily goal!`
            ]);
        }

    } catch (error) {
        console.error('Error checking goal reminders:', error);
    } finally {
        if (connection) connection.release();
    }
}

// Function to check due follow-ups
async function checkDueFollowUps() {
    let connection;
    try {
        connection = await pool.getConnection();
        
        const [dueFollowUps] = await connection.execute(`
            SELECT f.user_id, f.id, b.business_name, u.name
            FROM follow_ups f
            JOIN businesses b ON f.business_id = b.id
            JOIN users u ON f.user_id = u.id
            WHERE f.status = 'scheduled'
              AND DATE(f.scheduled_date) = CURDATE()
              AND f.id NOT IN (
                  SELECT CAST(SUBSTRING_INDEX(action_url, '/', -1) AS UNSIGNED)
                  FROM notifications 
                  WHERE type = 'task_due' 
                    AND DATE(created_at) = CURDATE()
                    AND action_url LIKE '/follow-ups/%'
              )
        `);

        for (const followUp of dueFollowUps) {
            await connection.execute(`
                INSERT INTO notifications (user_id, title, message, type, priority, action_url)
                VALUES (?, ?, ?, 'task_due', 'high', ?)
            `, [
                followUp.user_id,
                'Follow-up Due Today',
                `You have a follow-up scheduled today with ${followUp.business_name}`,
                `/follow-ups/${followUp.id}`
            ]);
        }

    } catch (error) {
        console.error('Error checking due follow-ups:', error);
    } finally {
        if (connection) connection.release();
    }
}

// Run background tasks every hour
setInterval(() => {
    checkGoalReminders();
    checkDueFollowUps();
}, 60 * 60 * 1000); // Every hour

// Run once on startup (after 30 seconds to ensure DB is ready)
setTimeout(() => {
    checkGoalReminders();
    checkDueFollowUps();
}, 30000);
