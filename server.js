import express from 'express';
import tls from 'tls';
import mysql from 'mysql2/promise';
import cors from 'cors';
import dotenv from 'dotenv';
import { fileURLToPath } from 'url';
import { dirname } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

// Middleware to log requests
app.use((req, res, next) => {
    console.log(`${req.method} ${req.url}`);
    
    // Only log db_pass for database-related endpoints
    if (req.url.includes('/api/test-connection')) {
        console.log('Request body:', {
            ...req.body,
            db_pass: req.body.db_pass ? '[HIDDEN]' : undefined // Hide password in logs
        });
    } else {
        console.log('Request body:', req.body);
    }
    
    next();
});

app.post('/api/test-connection', async (req, res) => {
    const { db_host, db_name, db_user, db_pass } = req.body;

    // Validate required fields (password can be empty)
    if (!db_host || !db_name || !db_user) {
        const error = 'Host, database name, and username are required';
        console.error('Missing required fields:', { 
            host: !!db_host, 
            database: !!db_name, 
            user: !!db_user 
        });
        return res.json({
            success: false,
            message: 'Missing required fields',
            error
        });
    }

    try {
        console.log('Attempting to connect to database with config:', {
            host: db_host,
            user: db_user,
            database: db_name,
            // password omitted for security
        });

        // Create connection with a timeout
        const connection = await mysql.createConnection({
            host: db_host,
            user: db_user,
            password: db_pass === undefined ? '' : db_pass, // Handle undefined, null, or empty string
            database: db_name,
            connectTimeout: 10000, // 10 seconds timeout
            waitForConnections: true
        });

        // Test the connection
        await connection.connect();
        console.log('Database connection successful');
        
        // Verify database exists by running a simple query
        try {
            await connection.query('SELECT 1');
            console.log('Database query successful');
            await connection.end();
            
            return res.json({ 
                success: true, 
                message: 'Database connection successful!',
                details: {
                    host: db_host,
                    database: db_name,
                    user: db_user
                }
            });
        } catch (queryError) {
            console.error('Database query error:', queryError.message);
            return res.json({
                success: false,
                message: 'Database connection failed',
                error: `Database exists but query failed: ${queryError.message}`,
                details: {
                    errorCode: queryError.code,
                    sqlState: queryError.sqlState,
                    sqlMessage: queryError.sqlMessage
                }
            });
        }
    } catch (error) {
        console.error('Database connection error:', error.message);
        
        let errorMessage = error.message;
        let errorDetails = {
            errorCode: error.code,
            sqlState: error.sqlState,
            sqlMessage: error.sqlMessage
        };
        
        // Make error messages more user-friendly
        if (error.message.includes('ER_ACCESS_DENIED_ERROR')) {
            errorMessage = 'Access denied. Please check your username and password.';
        } else if (error.message.includes('ECONNREFUSED')) {
            errorMessage = 'Could not connect to database server. Please check if the server is running and the host is correct.';
        } else if (error.message.includes('ER_BAD_DB_ERROR')) {
            errorMessage = 'Database does not exist.';
        } else if (error.message.includes('ETIMEDOUT')) {
            errorMessage = 'Connection timed out. Please check your host and port.';
        }

        return res.json({ 
            success: false, 
            message: 'Database connection failed', 
            error: errorMessage,
            details: errorDetails
        });
    }
});

app.get('/check-ssl', async (req, res) => {
    const domain = req.query.domain;
    if (!domain) return res.status(400).json({ error: 'Please provide ?domain=example.com' });

    const options = {
        host: domain,
        port: 443,
        servername: domain,
        rejectUnauthorized: false,
    };

    const socket = tls.connect(options, () => {
        const cert = socket.getPeerCertificate();
        const tlsVersion = socket.getProtocol();
        socket.end();

        if (!cert || !cert.valid_to) {
            return res.json({
                domain,
                ssl: false,
                score: 0,
                message: 'No valid SSL certificate found.',
                last_checked: new Date().toISOString()
            });
        }

        const validFrom = new Date(cert.valid_from);
        const validTo = new Date(cert.valid_to);
        const now = new Date();

        const daysRemaining = Math.round((validTo - now) / (1000 * 60 * 60 * 24));

        // Simple scoring
        let score = 100;
        if (daysRemaining < 30) score -= 30;
        else if (daysRemaining < 90) score -= 10;
        if (tlsVersion && !tlsVersion.includes('1.3')) score -= 20;

        return res.json({
            domain,
            ssl: true,
            score,
            valid_from: validFrom.toISOString(),
            valid_to: validTo.toISOString(),
            days_remaining: daysRemaining,
            tls_version: tlsVersion,
            last_checked: new Date().toISOString()
        });
    });

    socket.on('error', (err) => {
        return res.json({
            domain,
            ssl: false,
            score: 0,
            error: err.message,
            last_checked: new Date().toISOString()
        });
    });
});

const PORT = process.env.VITE_BACKEND_PORT || 3001;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
}); 