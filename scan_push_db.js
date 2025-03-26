
// async function scanDependencies() {
//     try {
//         const response = await fetch('http://127.0.0.1:7070/scan', {
//             method: 'POST',
//             headers: {
//                 'Content-Type': 'application/json'
//             },
//             body: JSON.stringify({
//                 path: "E:/Semester6/IndividualProject/Project/source/test",
//                 type: "nodejs",
//                 profile: "generic"
//             })
//         });

//         const data = await response.json();

//         // Print full response
//         console.log('Full Response:', JSON.stringify(data, null, 2));

//         // Print specific parts
//         console.log('\n--- Dependencies ---');
//         data.components?.forEach(dep => {
//             console.log(`${dep.name}@${dep.version}`);
//         });

//         console.log('\n--- Vulnerabilities ---');
//         data.vulnerabilities?.forEach(vuln => {
//             console.log(`ID: ${vuln.id}`);
//             console.log(`Severity: ${vuln.severity}`);
//             console.log(`Description: ${vuln.description}`);
//             console.log('---');
//         });

//         // Save to file
//         const fs = require('fs');
//         fs.writeFileSync('scan-results.json', JSON.stringify(data, null, 2));

//     } catch (error) {
//         console.error('Error:', error);
//     }
// }

// scanDependencies();
import pkg from 'pg';
import { writeFileSync } from 'fs';
const { Client } = pkg;



async function scanDependencies() {
    try {
        // Add timeout and additional options
        const controller = new AbortController();
        // const timeoutId = setTimeout(() => controller.abort(), 300000); // 300 seconds timeout

        const response = await fetch('http://127.0.0.1:7070/scan', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            },
            body: JSON.stringify({
                path: "E:/Semester6/IndividualProject/Project/source/test",
                type: "nodejs",
                profile: "generic"
            }),
            // signal: controller.signal,
            // // Add these options to handle potential issues
            // keepalive: true,
            // timeout: 300000
        });

        // clearTimeout(timeoutId);

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        const data = await response.json();
        // Save to file
        writeFileSync('scan-results.json', JSON.stringify(data, null, 2));
        console.log("Scan results saved to scan-results.json");
        return data;
    } catch (error) {
        if (error.name === 'AbortError') { 
            console.error('Request timed out');
        } else {
            console.error('Error:', error);
        }
    }
    
}


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
            console.log("Affected Versions:", affectedVersions);
            console.log("Unaffected Versions:", unaffectedVersions);
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
    
    // Example PostgreSQL insertion (you'll need to modify based on your DB schema)
    // try {
    //     for (const record of vulnerabilityRecords) {
    //         await db.query(`
    //            INSERT INTO dev (
    //             cve_id, 
    //             package_url,
    //             affected_version,
    //             severity,
    //             cvss_score, 
    //             fix_version, 
    //             recommendation,
    //             insights
    //             )
    //             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
    //             ON CONFLICT (id) DO NOTHING;
    //         `, [
    //             record.vulnerability_id,
    //             record.package,
    //             record.score,
    //             record.severity,
    //             record.recommendation,
    //             record.affected_package,
    //             record.affected_versions,
    //             record.unaffected_versions,
    //             record.insights
    //         ]);
    //     }
    //     console.log(`Successfully processed ${vulnerabilityRecords.length} vulnerabilities`);
    // } catch (error) {
    //     console.error('Error inserting vulnerability records:', error);
    //     throw error;
    // }
    console.log(`Processed ${vulnerabilityRecords.length} vulnerability records`);
    console.log(vulnerabilityRecords);
    return vulnerabilityRecords;
}

// async function insertData(vulnerabilityRecords) {
//     // insert data into database
//     try {
//         for (const record of vulnerabilityRecords) {
//             await db.query(`
//                 INSERT INTO vulnerabilities (
//                     vulnerability_id,
//                     score,
//                     severity,
//                     description,
//                     recommendation,
//                     affected_package,
//                     affected_versions,
//                     insights
//                 ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
//             `, [
//                 record.vulnerability_id,
//                 record.score,
//                 record.severity,
//                 record.description,
//                 record.recommendation,
//                 record.affected_package,
//                 JSON.stringify(record.affected_versions), // Store versions as JSON
//                 record.insights
//             ]);
//         }
//         console.log(`Successfully processed ${vulnerabilityRecords.length} vulnerabilities`);
//     } catch (error) {
//         console.error('Error inserting vulnerability records:', error);
//         throw error;
//     }
// }

  
  async function insertData(vulnerabilityRecords) {
    const db = new Client({
        user: 'postgres',
        host: 'localhost',
        database: 'dev',
        password: 'Admin@123456',
        port: 5432,
      });

    try {
      // Connect to PostgreSQL
      await db.connect();
      for (const record of vulnerabilityRecords) {
        await db.query(`
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
         `, [
             record.vulnerability_id,
             record.package,
             record.affected_versions,
             record.severity,
             record.score,
             record.unaffected_versions,
             record.recommendation,
             record.insights
         ]);
      }
  
      console.log("Data insertion complete!");
    } catch (err) {
      console.error("Error inserting data", err);
    } finally {
      // Close the connection
      await db.end();
    }
}


async function main() {
    const data = await scanDependencies();
    // console.log('Scan results:', JSON.stringify(data, null, 2));
    const vulnerabilityRecords = await  processVulnerabilityData(data);
    console.log("Vulnerability Records:", vulnerabilityRecords);
    // console.log("Vulnerability Records:", vulnerabilityRecords);
    await insertData(vulnerabilityRecords);
}

main().catch(error => console.error('Main error:', error));



// async function scanDependencies() {
//     try {
//         // Add timeout and additional options
//         const controller = new AbortController();
//         // const timeoutId = setTimeout(() => controller.abort(), 300000); // 300 seconds timeout

//         const response = await fetch('http://127.0.0.1:7070/scan', {
//             method: 'POST',
//             headers: {
//                 'Content-Type': 'application/json',
//                 'Accept': 'application/json'
//             },
//             body: JSON.stringify({
//                 path: "E:/Semester6/IndividualProject/Project/source/test",
//                 type: "nodejs",
//                 profile: "generic"
//             }),
//             // signal: controller.signal,
//             // // Add these options to handle potential issues
//             // keepalive: true,
//             // timeout: 300000
//         });

//         // clearTimeout(timeoutId);

//         if (!response.ok) {
//             throw new Error(`HTTP error! status: ${response.status}`);
//         }

//         const data = await response.json();
//         // Save to file
//         writeFileSync('scan-results.json', JSON.stringify(data, null, 2));
//         console.log("Scan results saved to scan-results.json");
//         return data;
//     } catch (error) {
//         if (error.name === 'AbortError') { 
//             console.error('Request timed out');
//         } else {
//             console.error('Error:', error);
//         }
//     }
    
// }
// In your frontend JavaScript
// document.getElementById('submitBtn').addEventListener('click', async function(e) {
//     e.preventDefault();
//     const directoryPath = document.getElementById('directoryPath').value;
    
//     try {
//         const headers = {'Content-Type':'application/json',
//             'Access-Control-Allow-Origin':'*',
//             'Access-Control-Allow-Methods':'POST,PATCH,OPTIONS'}
//         const response = await fetch('http://localhost:7070/scan', {
//             method: 'POST',
//             headers: headers,
//             body: JSON.stringify({ path: directoryPath })
//         });
        
//         const result = await response.json();
//         console.log('Scan result:', result);
//     } catch (error) {
//         console.error('Error:', error);
//     }
// });