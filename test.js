
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
        });
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


async function processDependencyData(data) {
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
            // console.log(test);
            const packageName = packageWithVersion.split('@')[0];
            const packageVersion = packageWithVersion.split('@')[1];
            // console.log("Package Name:", packageName);
            // console.log("Package Version:", packageVersion);
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
    console.log(`Processed ${dependencyRecords.length} dependency records`);
    console.log(dependencyRecords);
    return dependencyRecords;
}



  
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
    const packageName = "lodash";
    // console.log('Scan results:', JSON.stringify(data, null, 2));
    const Records = await  processDependencyData(data);
    console.log("Vulnerability Records:", Records);
    // console.log("Vulnerability Records:", vulnerabilityRecords);
    // await insertData(vulnerabilityRecords);
}

main().catch(error => console.error('Main error:', error));



