// const express = require('express');
// const { Pool } = require('pg');
// const cors = require('cors');
import express from 'express';
import pkg from 'pg';
import cors from 'cors';
import * as dotenv from 'dotenv';
import fetch from 'node-fetch';
import axios from "axios";
import {writeFileSync} from "fs";
import https from 'https';

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
            LIMIT 10;
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

app.get('/api/vulnerabilities/total', async (req, res) => {
    try {
        const query = `SELECT COUNT(*) FROM dev;`;
        const result = await pool.query(query);
        res.json({ total: parseInt(result.rows[0].count) });
        // res.json(result.rows[0]);
    } catch (error) {
        console.error('Database Error:', error);
        res.status(500).json({ 
            error: 'Internal server error',
            details: error.message 
        });
    }
});
// Scan result endpoint
app.get('/api/vulnerabilities/scan-result', async (req, res) => {
    try {
        const query = `
        select * from scan_result where scan_id=(select max(scan_id) from scan_result);
        `;
        const result = await pool.query(query);
        res.json(result.rows);
    } catch (error) {
        console.error('Database Error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});
/// Get Total Critical Vulnerability that was scanned
app.get('/api/vulnerabilities/critical', async (req, res) => {
    try {
        const query = `select count(*) from dev where severity="critical";`;
        const result = await pool.query(query);
        res.json({ total: parseInt(result.rows[0].count) })
    } catch (error) {
        console.log('Database Error: ', error);
        res.status(500).json({ error: 'Internal server error '});
    }
});

//// dependency scan endpoint
app.get('/api/dependency-scan', async (req, res) => {
    try {
        const query = `select * from dependency_scan where scan_id=(select max(scan_id) from dependency_scan);`;
        const result = await pool.query(query);
        res.json(result.rows);
    }
    catch (error) {
        console.error('Database Error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});
app.get('/api/dependency-scan/unmanaged/total', async (req,res) => {
    try {
        const query = `select count(*) from dependency_scan where insights="unmanaged";`;
        const result = await pool.query(query);
        res.json({ total: parseInt(result.rows[0].count) });
    }
    catch (error){
        console.error('Database Error: ', error);
        res.status(500).json({error: 'Internal Server Error'});
    }
});
/// get total managed package was scanned
app.get('/api/dependency-scan/managed/total', async (req,res) => {
    try {
        const query = `select count(*) from dependency_scan where insight="managed";`;
        const result = pool.query(query);
        res.json({ total: parseInt(result.rows[0].count) });
    } catch (error) {
        console.error('Database Error: ', error);
        res.status(500).json({error: 'Internal Server Error'});
    }
});
//save to dependency_scan table
app.post('/save-dependency-scan', async (req, res) => {
    const scanData = req.body.scanData;
    let dependencyRecords = [];
    let insights = "";
    try {
        const dataRecords = await retrieveDependencyNameAndVersion(scanData);
        for (const item of dataRecords) {
            const packageName = item.package;
            const packageVersion = item.version;
            const latestVersion = await getNpmPackageLatestVersion(packageName).catch(() => 'N/A');
            const latestPublishDate = await getNpmPackageLatestPublishDate(packageName).catch(() => 'N/A');
            const weeklyDownloads = await downloadsCountPerVersion(packageName, packageVersion).catch(() => 0);
            const isMaintained = await isPackageBeingMaintained(packageName).catch(() => false);
            if (isMaintained === true) {
                insights = "Maintained";
            } else {
                insights = "Unmaintained";
            }
            const record = {
                package: packageName,
                version: packageVersion,
                latestVersion: latestVersion || 'N/A',
                latestPublishDate: latestPublishDate || 'N/A',
                weeklyDownloads: weeklyDownloads || 0,
                insights: insights
            }
            dependencyRecords.push(record);
        }
        // console.log("record ", dependencyRecords);
        await insertDependencyScanData(dependencyRecords);
        res.status(200).json({ message: 'Dependency scan data saved successfully!' });
    } catch (error) {
        console.error('Error saving scan data:', error);
        res.status(500).json({ error: 'Failed to save scan data.' });
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
    const scanData = req.body.scanData;
    if (!scanData) {
        return res.status(400).json({ error: 'No scan data found.' });
    }

    try {
        const finalData = await processVulnerabilityData(scanData);
        await insertScanResultData(finalData);
        console.log("done inserting data scan result");
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
        await insertVulnerabilityData(finalData);
        console.log("done inserting data dev");
        res.status(200).json({ message: 'Scan data saved successfully!' });
    } catch (error) {
        console.error('Error saving scan data:', error);
        res.status(500).json({ error: 'Failed to save scan data.' });
    }
});


////////////////////////////////////////////////////////////
async function getScanId(tableName) {
    const query = `SELECT MAX(scan_id) FROM ${tableName}`;
    const result = await pool.query(query);
    if (result.rows.length === 0) {
        return 0;
    }
    return result.rows[0].max;
}
async function insertScanResultData(records) {
    try {
        const tableName = "scan_result";
        let scanId = await getScanId(tableName);
        console.log("Scan ID:", scanId);
        if (scanId === null) {
            scanId = 0;
            console.log("Scan ID is null, setting to 0");
        } else {
            console.log("Scan ID is not null, incrementing by 1");
            scanId++;
        }
        for (const record of records) {
            console.log("scan id record:", scanId);
            const query = `
                INSERT INTO scan_result (
                cve_id, 
                scan_id,
                package_url,
                affected_version,
                severity,
                cvss_score, 
                fix_version, 
                recommendation,
                insights
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            `;
            const values = [
                record.vulnerability_id,
                scanId,
                record.package,
                record.affected_versions,
                record.severity,
                record.score,
                record.unaffected_versions,
                record.recommendation,
                record.insights
            ];

            console.log("Executing query with values:", values);  // Log values being inserted
            await pool.query(query, values); 
        }

        console.log("Data insertion complete!");
    } catch (err) {
      console.error("Error inserting data", err);
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
                ON CONFLICT (cve_id) DO NOTHING;
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
    } 
}

//// insert data to dependency_scan table
async function insertDependencyScanData(records) {
    try {
        const tableName = "dependency_scan";
        let scanId = await getScanId(tableName);
        console.log("Scan ID:", scanId);
        if (scanId === null) {
            scanId = 0;
            console.log("Scan ID is null, setting to 0");
        } else {
            console.log("Scan ID is not null, incrementing by 1");
            scanId++;
        }
        for (const record of records) {
            console.log("scan id record:", scanId);
            const query = `
                INSERT INTO dependency_scan ( 
                scan_id,
                package_name,
                current_version,
                latest_version, 
                latest_publish_date,
                weekly_downloads,
                insights
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7)
            `;
            const values = [
                scanId,
                record.package,
                record.version,
                record.latestVersion,
                record.latestPublishDate,
                record.weeklyDownloads,
                record.insights
            ];

            console.log("Executing query with values:", values);  // Log values being inserted
            await pool.query(query, values); 
        }

        console.log("Data insertion complete!");
    } catch (err) {
      console.error("Error inserting data", err);
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
///// get weekly downloads count per version
async function downloadsCountPerVersion(packageName, packageVersion) {
    try {
        const response = await axios.get(
            `https://api.npmjs.org/versions/${packageName}/last-week`,
            {
                httpsAgent: new https.Agent({ rejectUnauthorized: false })
            }
        );
        return response.data.downloads[packageVersion];
    } catch (error) {
        console.error('Error fetching download counts:', error.message);
        return 0;
    }
}
///// get latest version and latest publish date
async function getNpmPackageLatestVersion(packageName) {
    try {
        const response = await axios.get(`https://registry.npmjs.org/${packageName}`);
        const data = response.data;
        const latestVersion = data['dist-tags'].latest;
        // console.log(`Latest Version: ${latestVersion}`);
        return latestVersion;
    } catch (error) {
        console.error('Error fetching package latest version info:', error.message);
    }
}
//// get latest publish date
async function getNpmPackageLatestPublishDate(packageName) {
    try {
        const response = await axios.get(`https://registry.npmjs.org/${packageName}`);
        const data = response.data;
        const latestVersion = data['dist-tags'].latest;
        const publishDate = data.time[latestVersion];
        // console.log(`Latest Published: ${new Date(publishDate).toLocaleDateString()}`);
        return publishDate;
    } catch (error) {
        console.error('Error fetching package latest publish date info:', error.message);
    }
}
/// Modify the data for dependency scan
async function retrieveDependencyNameAndVersion(data) {
    // Array to store processed dependency records
    const dependencyRecords = [];
    
    // Check if data exist
    if (!data || !data.dependencies) {
        console.log("No dependency data found");
        return dependencyRecords;
    }
    
    for (const dep of data.dependencies) {
        try {
            const ref = dep.ref;
            const packageWithVersion = ref.split('/').pop();
            // const test = packageWithVersion.split('@');
            const packageName = packageWithVersion.split('@')[0];
            const packageVersion = packageWithVersion.split('@')[1];
            const record = {
                package: packageName,
                version: packageVersion
            }
            dependencyRecords.push(record);
        } catch (error) {
            console.error('Error processing dependency:', error);
            continue; // Skip this vulnerability and continue with the next one
        }
    }
    return dependencyRecords;
}

/// Check if the package is being maintained
async function isPackageBeingMaintained(packageName) {
    const latestPublishDate = await getNpmPackageLatestPublishDate(packageName);
    const now = new Date();
    const latestPublishDateObj = new Date(latestPublishDate);
    const diffTime = Math.abs(now - latestPublishDateObj);
    const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24)); 
    return diffDays <= 180;
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


