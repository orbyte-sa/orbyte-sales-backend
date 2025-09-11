// 1. IMPORTS
const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
require('dotenv').config();

// 2. APP INITIALIZATION & CORE MIDDLEWARE
const app = express();
const PORT = process.env.PORT || 10000;

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

// 3. CONFIGURATIONS
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

const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'uploads/')
    },
    filename: function (req, file, cb) {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
    }
});

// 4. INITIALIZATIONS
const pool = mysql.createPool(poolConfig);
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
const JWT_SECRET = process.env.JWT_SECRET || 'orbyte_sales_secret_key_2025';

// 5. HELPER FUNCTIONS & CUSTOM MIDDLEWARE
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

const requireAdmin = (req, res, next) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Admin access required' });
    }
    next();
};

const requireDB = (req, res, next) => {
    if (dbConnectionStatus.startsWith('error:') || dbConnectionStatus === 'unknown') {
        return res.status(503).json({ error: 'Database connection not available' });
    }
    next();
};

async function getOrCreateBusiness(pool, businessData) {
    const { business_name, contact_person, contact_position, contact_phone, contact_email, created_by } = businessData;
    const [existing] = await pool.query('SELECT id FROM businesses WHERE business_name = ?', [business_name]);
    if (existing.length > 0) {
        return existing[0].id;
    } else {
        const sql = `
            INSERT INTO businesses 
            (business_name, contact_person, contact_position, phone, email, created_by, status) 
            VALUES (?, ?, ?, ?, ?, ?, ?)
        `;
        const values = [business_name, contact_person, contact_position, contact_phone, contact_email, created_by, 'Contacted'];
        const [result] = await pool.query(sql, values);
        return result.insertId;
    }
}

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

// Initialize database connection
testConnection();


// 6. API ROUTES

// Health check endpoint
app.get('/api/health', async (req, res) => {
    const health = {
        status: 'OK',
        message: 'Orbyte Sales API is running',
        timestamp: new Date().toISOString(),
        environment: process.env.NODE_ENV || 'development',
        database: dbConnectionStatus
    };
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

// TASK ROUTES
app.get('/api/tasks/:id', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;
        const sql = `
            SELECT 
                t.*,
                u_assigned.name as assigned_user_name,
                u_creator.name as assigned_by_name,
                b.business_name,
                b.contact_person,
                b.contact_position,
                b.phone as business_phone,
                b.email as business_email,
                b.address as business_address
            FROM tasks t
            LEFT JOIN users u_assigned ON t.assigned_to = u_assigned.id
            LEFT JOIN users u_creator ON t.assigned_by = u_creator.id
            LEFT JOIN businesses b ON t.business_id = b.id
            WHERE t.id = ?
        `;
        const [tasks] = await pool.query(sql, [id]);

        if (tasks.length === 0) {
            return res.status(404).json({ error: 'Task not found' });
        }
        res.json(tasks[0]);
    } catch (error) {
        console.error('Error fetching task details:', error);
        res.status(500).json({ error: 'Failed to fetch task details' });
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

        // FIXED: Users can see tasks assigned TO them OR assigned BY them
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

 // ... your POST task logic ...
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

// ... your PUT task logic ...
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

// PUT (update) bulk assign tasks
app.put('/api/tasks/bulk-assign', authenticateToken, async (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Forbidden' });
    }
    const { taskIds, assignedTo } = req.body;
    if (!taskIds || !Array.isArray(taskIds) || !assignedTo) {
        return res.status(400).json({ error: 'Invalid request: taskIds and assignedTo are required.' });
    }

    try {
        const sql = 'UPDATE tasks SET assigned_to = ? WHERE id IN (?)';
        await pool.query(sql, [assignedTo, taskIds]);
        res.status(200).json({ message: 'Tasks reassigned successfully.' });
    } catch (error) {
        console.error('Error bulk assigning tasks:', error);
        res.status(500).json({ error: 'Failed to reassign tasks.' });
    }
});

// DELETE bulk delete tasks
app.delete('/api/tasks/bulk-delete', authenticateToken, async (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Forbidden' });
    }
    const { taskIds } = req.body;
    if (!taskIds || !Array.isArray(taskIds)) {
        return res.status(400).json({ error: 'Invalid request: taskIds array is required.' });
    }

    try {
        const sql = 'DELETE FROM tasks WHERE id IN (?)';
        await pool.query(sql, [taskIds]);
        res.status(200).json({ message: 'Tasks deleted successfully.' });
    } catch (error) {
        console.error('Error bulk deleting tasks:', error);
        res.status(500).json({ error: 'Failed to delete tasks.' });
    }
});


// =============================================================================
// USER MANAGEMENT ROUTES
// =============================================================================

 // ... your GET users logic ...
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

// REPORT ROUTES
app.post('/api/reports/cold-calling', [authenticateToken, upload.single('photo_proof')], async (req, res) => {
    try {
        let { business_id, ...reportData } = req.body;
        const userId = req.user.id;
        
        // If no business_id is linked, find or create the business
        if (!business_id || business_id === 'null' || business_id === '') {
            business_id = await getOrCreateBusiness(pool, { ...reportData, created_by: userId });
        }

        const photo_proof = req.file ? req.file.filename : null;
        const sql = `
            INSERT INTO cold_calling_reports 
            (user_id, business_name, business_id, contact_person, contact_position, contact_phone, contact_email, visit_time, outcome, notes, latitude, longitude, photo_proof, follow_up_required, follow_up_date) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `;
        const values = [
            userId, reportData.business_name, business_id, reportData.contact_person, reportData.contact_position, 
            reportData.contact_phone, reportData.contact_email, reportData.visit_time, reportData.outcome, 
            reportData.notes, reportData.latitude || null, reportData.longitude || null, photo_proof, 
            reportData.follow_up_required === 'true', reportData.follow_up_date || null
        ];

        await pool.query(sql, values);
        res.status(201).json({ message: 'Cold calling report created successfully' });
    } catch (error) {
        console.error('Error creating cold calling report:', error);
        res.status(500).json({ error: 'Failed to create report' });
    }
});

app.post('/api/reports/telemarketing', [authenticateToken, upload.none()], async (req, res) => {
    try {
        let { business_id, ...reportData } = req.body;
        const userId = req.user.id;

        // If no business_id is linked, find or create the business
        if (!business_id || business_id === 'null' || business_id === '') {
            business_id = await getOrCreateBusiness(pool, { ...reportData, created_by: userId });
        }

        const sql = `
            INSERT INTO telemarketing_reports 
            (user_id, business_name, business_id, contact_person, contact_position, contact_phone, contact_email, call_time, outcome, notes, follow_up_required, follow_up_date) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `;
        const values = [
            userId, reportData.business_name, business_id, reportData.contact_person, reportData.contact_position, 
            reportData.contact_phone, reportData.contact_email, reportData.call_time, reportData.outcome, 
            reportData.notes, reportData.follow_up_required === 'true', reportData.follow_up_date || null
        ];

        await pool.query(sql, values);
        res.status(201).json({ message: 'Telemarketing report created successfully' });
    } catch (error) {
        console.error('Error creating telemarketing report:', error);
        res.status(500).json({ error: 'Failed to create report' });
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
// PHOTO ACCESS ROUTE - For viewing uploaded photos
// =============================================================================

app.get('/api/reports/photo/:filename', authenticateToken, (req, res) => {
    try {
        const { filename } = req.params;
        const photoPath = path.join(__dirname, 'uploads', filename);
        
        // Check if file exists
        if (!fs.existsSync(photoPath)) {
            return res.status(404).json({ error: 'Photo not found' });
        }
        
        // Set appropriate headers for image display
        const ext = path.extname(filename).toLowerCase();
        const mimeTypes = {
            '.jpg': 'image/jpeg',
            '.jpeg': 'image/jpeg',
            '.png': 'image/png',
            '.gif': 'image/gif',
            '.webp': 'image/webp'
        };
        
        const mimeType = mimeTypes[ext] || 'application/octet-stream';
        res.setHeader('Content-Type', mimeType);
        res.setHeader('Cache-Control', 'public, max-age=31536000'); // Cache for 1 year
        
        res.sendFile(photoPath);
        
    } catch (error) {
        console.error('Photo access error:', error);
        res.status(500).json({ error: 'Failed to access photo' });
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

// DELETE multiple reports
app.delete('/api/reports/bulk-delete', authenticateToken, async (req, res) => {
    // Security Check: Only admins can perform bulk delete
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Forbidden' });
    }

    const { reports } = req.body; // Expecting an array of { id, type }
    if (!reports || !Array.isArray(reports) || reports.length === 0) {
        return res.status(400).json({ error: 'Invalid request body' });
    }

    const connection = await pool.getConnection();
    try {
        await connection.beginTransaction();

        for (const report of reports) {
            if (report.type === 'cold_calling') {
                await connection.query('DELETE FROM cold_calling_reports WHERE id = ?', [report.id]);
            } else if (report.type === 'telemarketing') {
                await connection.query('DELETE FROM telemarketing_reports WHERE id = ?', [report.id]);
            }
        }

        await connection.commit();
        res.status(200).json({ message: 'Reports deleted successfully' });
    } catch (error) {
        await connection.rollback();
        console.error('Error during bulk report delete:', error);
        res.status(500).json({ error: 'Failed to delete reports' });
    } finally {
        connection.release();
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
// ENHANCED REPORT ROUTES - Add detailed view for management
// =============================================================================


// Get single report with full details
app.get('/api/reports/:type/:id', authenticateToken, requireDB, async (req, res) => {
    let connection;
    try {
        const { type, id } = req.params;
        
        if (!['cold_calling', 'telemarketing'].includes(type)) {
            return res.status(400).json({ error: 'Invalid report type' });
        }

        connection = await pool.getConnection();
        
        const [reports] = await connection.execute(`
            SELECT cr.*, u.name as user_name, u.department, u.executive_type,
                   b.business_name as linked_business_name, b.contact_person as linked_contact_person,
                   b.phone as linked_phone, b.email as linked_email, b.address as linked_address
            FROM comprehensive_reports cr
            LEFT JOIN users u ON cr.user_id = u.id
            LEFT JOIN businesses b ON cr.business_id = b.id
            WHERE cr.report_type = ? AND cr.id = ?
        `, [type, id]);

        if (reports.length === 0) {
            return res.status(404).json({ error: 'Report not found' });
        }

        const report = reports[0];

        // Check permissions - admin can see all, users can see their own
        if (req.user.role !== 'admin' && report.user_id !== req.user.id) {
            return res.status(403).json({ error: 'Access denied' });
        }

        // Get follow-ups for this report
        const [followUps] = await connection.execute(`
            SELECT * FROM follow_ups 
            WHERE report_id = ? AND report_type = ?
            ORDER BY scheduled_date DESC
        `, [id, type]);

        res.json({
            ...report,
            follow_ups: followUps
        });

    } catch (error) {
        console.error('Get report details error:', error);
        res.status(500).json({ error: 'Failed to fetch report details' });
    } finally {
        if (connection) connection.release();
    }
});

// Enhanced reports list with more details for management
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

// DELETE a business
app.delete('/api/businesses/:id', authenticateToken, async (req, res) => {
    // Security check: Only admins can delete businesses
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Forbidden: You do not have permission to perform this action.' });
    }

    try {
        const { id } = req.params;
        const [result] = await pool.query('DELETE FROM businesses WHERE id = ?', [id]);
        
        if (result.affectedRows === 0) {
            return res.status(404).json({ error: 'Business not found' });
        }
        
        res.status(200).json({ message: 'Business deleted successfully' });
    } catch (error) {
        console.error('Error deleting business:', error);
        res.status(500).json({ error: 'Failed to delete business' });
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

// 7. ERROR HANDLING & SERVER START
app.use((err, req, res, next) => {
    console.error('Error:', err);
    res.status(500).json({ error: 'Internal server error' });
});

app.use((req, res) => {
    res.status(404).json({ error: 'Endpoint not found' });
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
