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
    const { scanData } = req.body.scanData;
    console.log(scanData);
    // if (!finalData || !Array.isArray(scanData)) {
    //     return res.status(400).json({ error: 'Invalid data format. "scanData" must be an array.' });
    // }

    try {
        const finalData = processVulnerabilityData(scanData);
        await insertScanHistoryData(finalData);
        res.status(200).json({ message: 'Scan data saved successfully!' });
    } catch (error) {
        console.error('Error saving scan data:', error);
        res.status(500).json({ error: 'Failed to save scan data.' });
    }
});
// Backend API endpoint to save final data to dev table
app.post('/save-final-data-dev', async (req, res) => {
    const scanData = req.body.scanData;
    if (!scanData) {
        return res.status(400).json({ error: 'No scan data found.' });
    }
    try {
        const finalData = await processVulnerabilityData(scanData);
        // console.log("done processing data");
        // console.log("finalData:", finalData);
        // console.log("Number of records:", finalData.length);
        // console.log("First record sample:", finalData[0]);
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

    // console.log("Inserting data into dev table");
    // console.log("Number of records:", records.length);
    // console.log("First record sample:", records[0]);
    // console.log("inserting data into dev table");
    console.log("records:", records);
    try {
        for (const record of records) {
            console.log("record:", record);
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

        console.log("Data insertion complete!");
    } catch (err) {
      console.error("Error inserting data", err);
    } finally {
      // Close the connection
      await db.end();
    }
}
//// process data
async function processVulnerabilityData(data) {
    // Array to store processed vulnerability records
    const vulnerabilityRecords = [];
    // console.log("Received data:", data);
    // Check if data and vulnerabilities exist
    if (!data || !data.vulnerabilities) {
        console.log("No vulnerability data found");
        return vulnerabilityRecords;
    }
    
    for (const vuln of data.vulnerabilities) {
        try {
            // Get the vulnerability ID
            // console.log("Vulnerability:", vuln);
            const vulnId = Array.isArray(vuln.id) ? vuln.id[0] : vuln.id;
            // console.log("Processing vulnerability:", vulnId);

            const bomRef = Array.isArray(vuln["bom-ref"]) ? vuln["bom-ref"][0] : vuln["bom-ref"];
            const package_url = bomRef.split('/').slice(1).join('/') || '';
            

            // Get rating information with safe access
            const ratings = Array.isArray(vuln.ratings) ? vuln.ratings : vuln.ratings;
            const rating = ratings[0] || {};
            // console.log("Rating:", rating);
            
            // Get affected version info with safe access
            const affects = Array.isArray(vuln.affects) ? vuln.affects : [];
            const affect = affects[0] || {};
            const versions = affect.versions || [];
            
            // Find insights with safe access
            const properties = Array.isArray(vuln.properties) ? vuln.properties : [];
            const insightsProp = properties.find(p => p?.name === 'depscan:insights');
            const insights = insightsProp?.value || '';
            // define affected and unaffected versions
            const affectedVersions = versions
                .filter(v => v?.status === 'affected')
                .map(v => v?.version?.replace(/['"]+/g, '') || '')
                .join(', '); // Convert array to comma-separated string

            const unaffectedVersions = versions
                .filter(v => v?.status === 'unaffected')
                .map(v => v?.version?.replace(/['"]+/g, '') || '')
                .join(', '); // Convert array to comma-separated string
            
            const record = {
                vulnerability_id: vulnId || '',
                package: package_url || '',
                score: rating.score || null,
                severity: rating.severity || null,
                // description: (vuln.description || '')
                //     .replace(/\\n/g, ' ')
                //     .replace(/\\/g, '')
                //     .trim(),
                recommendation: vuln.recommendation || '',
                affected_package: affect.ref || '',
                // affected_versions: versions.map(v => ({
                //     version: v?.version || '',
                //     status: v?.status || ''
                // })),
                affected_versions: affectedVersions,
                unaffected_versions: unaffectedVersions,
                insights: insights
            };
            
            vulnerabilityRecords.push(record);
        } catch (error) {
            console.error('Error processing vulnerability:', error);
            continue; // Skip this vulnerability and continue with the next one
        }
    }
    return vulnerabilityRecords;
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

