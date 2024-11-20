import express from 'express';
import pool from '../database/database.js';
// import db from '../database/database.js';


// const router = express.Router();
// // Get latest vulnerability scans
// router.get('/latest', async (req, res) => {
//     try {
//         const query = `
//             SELECT 
//                 v.id,
//                 v.package_url AS packageUrl,
//                 v.affected_version AS affectedVersion,
//                 v.severity,
//                 v.cvss_score AS cvssScore,
//                 v.fix_version AS fixVersion,
//                 v.short_description AS shortDescription,
//                 v.recommendation,
//                 v.insights,
//                 v.created_at AS scanDate
//             FROM vulnerabilities v
//             WHERE v.scan_date = (
//                 SELECT MAX(scan_date) 
//                 FROM vulnerabilities
//             )
//             ORDER BY v.severity DESC, v.cvss_score DESC
//             LIMIT 10
//         `;

//         console.log('Executing query:', query);
//         const results = await db.query(query);
//         console.log('Query results:', results);
        
//         res.json({
//             success: true,
//             data: results.rows
//         });
//     } catch (error) {
//         console.error('Error details:', {
//             message: error.message,
//             stack: error.stack,
//             code: error.code,
//             detail: error.detail
//         });
        
//         res.status(500).json({
//             success: false,
//             error: 'Failed to fetch vulnerability data',
//             details: error.message
//         });
//     }
// });

// // Add this test endpoint
// router.get('/test', async (req, res) => {
//     try {
//         const result = await db.query('SELECT NOW()');
//         res.json({
//             success: true,
//             data: result.rows[0]
//         });
//     } catch (error) {
//         console.error('Test query failed:', error);
//         res.status(500).json({
//             success: false,
//             error: 'Database connection test failed',
//             details: error.message
//         });
//     }
// });

// export default router;
// const express = require('express');
const router = express.Router();

router.get('/api/vulnerabilities/latest', async (req, res) => {
    try {
        const query = `
            SELECT *
            FROM vulnerabilities
            WHERE scan_date = (
                SELECT MAX(scan_date)
                FROM vulnerabilities
            )
            ORDER BY severity DESC, cvss_score DESC;
        `;
        
        const result = await pool.query(query);
        res.json(result.rows);
    } catch (error) {
        console.error('Error fetching vulnerabilities:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

export default router;