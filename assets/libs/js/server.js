// const express = require('express');
// const { Pool } = require('pg');
// const cors = require('cors');
import express from 'express';
import pkg from 'pg';
import cors from 'cors';
import * as dotenv from 'dotenv';
import fetch from 'node-fetch';

dotenv.config();

const { Pool } = pkg;
const app = express();

// Add CORS and JSON middleware
app.use(cors());
app.use(express.json());
const SRV_PORT = process.env.PORT || 3000;
const PRXY_PORT = process.env.PORT || 3030;
// Add a basic test route
app.get('/test', (req, res) => {
    res.json({ message: 'Server is running!' });
});

// PostgreSQL connection configuration
const pool = new Pool({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_NAME,
    password: process.env.DB_PASSWORD,
    port: process.env.DB_PORT || 5432,
});

// Test database connection
pool.connect()
    .then(() => console.log('Successfully connected to PostgreSQL'))
    .catch(err => console.error('Database connection error:', err));

// Your existing endpoint
app.get('/api/vulnerabilities/latest', async (req, res) => {
    try {
        const query = `
            SELECT * FROM vulnerabilities_test 
            ORDER BY 
                scan_date DESC,
                CASE 
                    WHEN severity = 'CRITICAL' THEN 1
                    WHEN severity = 'HIGH' THEN 2
                    WHEN severity = 'MEDIUM' THEN 3
                    WHEN severity = 'LOW' THEN 4
                    ELSE 5
                END,
                cvss_score DESC
            LIMIT 5;
        `;
        const result = await pool.query(query);
        res.json(result.rows);
    } catch (error) {
        console.error('Database Error:', error);
        res.status(500).json({ 
            error: 'Internal server error',
            details: error.message 
        });
    }
});
// Proxy scan endpoint
// app.post('/proxy-scan', async (req, res) => {
//     try {
//         const response = await fetch('http://127.0.0.1:7070/scan', {
//             method: 'POST',
//             headers: {
//                 'Content-Type': 'application/json',
//             },
//             body: JSON.stringify(req.body)
//         });

//         const data = await response.json();
//         res.json(data);
//     } catch (error) {
//         console.error('Proxy error:', error);
//         res.status(500).json({ error: 'Proxy server error' });
//     }
// });


// Modified server startup
app.listen(SRV_PORT, '0.0.0.0', () => {
    console.log(`Server is running on port ${SRV_PORT}`);
    // console.log(`Proxy server running at http://localhost:${PRXY_PORT}`);
    console.log(`Test the server at: http://localhost:${SRV_PORT}/test`);
    console.log(`API endpoint at: http://localhost:${SRV_PORT}/api/vulnerabilities/latest`);
});

