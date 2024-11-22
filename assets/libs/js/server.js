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
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));
const SRV_PORT = process.env.PORT || 3000;
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
            SELECT * FROM dev
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
app.post('/proxy-scan', async (req, res) => {
    try {
        const response = await fetch('http://127.0.0.1:7070/scan', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(req.body)
        });

        const data = await response.json();
        res.json(data);
    } catch (error) {
        console.error('Proxy error:', error);
        res.status(500).json({ error: 'Proxy server error' });
    }
});

// Backend API endpoint to save final data to scan_result table
app.post('/save-final-data', async (req, res) => {
    const { finalData } = req.body.finalData;
    console.log(finalData);
    if (!finalData || !Array.isArray(finalData)) {
        return res.status(400).json({ error: 'Invalid data format. "finalData" must be an array.' });
    }

    try {
        await insertScanHistoryData(finalData);
        res.status(200).json({ message: 'Scan data saved successfully!' });
    } catch (error) {
        console.error('Error saving scan data:', error);
        res.status(500).json({ error: 'Failed to save scan data.' });
    }
});
// Backend API endpoint to save final data to dev table
app.post('/save-final-data-dev', async (req, res) => {
    const { finalData } = req.body.finalData;
    console.log(finalData);
    if (!finalData || !Array.isArray(finalData)) {
        return res.status(400).json({ error: 'Invalid data format. "finalData" must be an array.' });
    }

    try {
        await insertVulnerabilityData(finalData);
        res.status(200).json({ message: 'Scan data saved successfully!' });
    } catch (error) {
        console.error('Error saving scan data:', error);
        res.status(500).json({ error: 'Failed to save scan data.' });
    }
});


////////////////////////////////////////////////////////////
async function getScanId() {
    const query = 'SELECT MAX(scan_id) FROM vulnerabilities';
    const result = await pool.query(query);
    return result.rows[0].max || 0;
}
async function insertScanResultData(records) {
    try {
        await pool.query('BEGIN');
        let scanId = await getScanId();
        console.log("Scan ID:", scanId);
        scanId++;
        for (const record of records) {
            const query = `
                INSERT INTO scan_history (
                id, 
                scan_id,
                purl,
                version,
                severity,
                cvss_score, 
                fix_version, 
                recommendation,
                insights
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                ON CONFLICT (id) DO NOTHING;
            `;
            const values = [
                record.vulnerability_id,
                scanId,
                record.package,
                record.score,
                record.severity,
                record.recommendation,
                record.affected_package,
                record.affected_versions,
                record.unaffected_versions,
                record.insights
            ];

            await pool.query(query, values);
        }

        await pool.query('COMMIT');
    } catch (error) {
        await pool.query('ROLLBACK');
        console.error('Error inserting vulnerability data:', error);
        throw error;
    } finally {
        await pool.end();
    }
}

async function insertVulnerabilityData(records) {

    try {
        await pool.query('BEGIN');
        for (const record of records) {
            const query = `
                INSERT INTO dev (
                cve_id, 
                package_url,
                affected_version,
                severity,
                cvss_score, 
                fix_version, 
                recommendation,
                insights
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                ON CONFLICT (id) DO NOTHING;
            `;
            const values = [
                record.vulnerability_id,
                record.package,
                record.affected_versions,
                record.severity,
                record.score,
                record.unaffected_versions,
                record.recommendation,
                record.insights
            ];

            await pool.query(query, values);
        }

        await pool.query('COMMIT');
    } catch (error) {
        await pool.query('ROLLBACK');
        console.error('Error inserting vulnerability data:', error);
        throw error;
    } finally {
        await pool.end();
    }
}



// Modified server startup
app.listen(SRV_PORT, '0.0.0.0', () => {
    console.log('\n=== Server Status ===');
    console.log(`Main server running on port ${SRV_PORT}`);
    console.log(`Proxy endpoint available at: http://localhost:${SRV_PORT}/proxy-scan`);
    console.log('\n=== Available Endpoints ===');
    console.log(`Test endpoint: http://localhost:${SRV_PORT}/test`);
    console.log(`API endpoint: http://localhost:${SRV_PORT}/api/vulnerabilities/latest`);
});

