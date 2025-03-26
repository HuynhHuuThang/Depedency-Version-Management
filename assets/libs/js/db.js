import pkg from 'pg';
const { Client } = pkg;
import * as dotenv from 'dotenv';
dotenv.config();


dotenv.config();


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
            const affectedVersions = versions.filter(v => v?.status === 'affected').map(v => v?.version?.replace(/['"]+/g, '') || '');
            const unaffectedVersions = versions.filter(v => v?.status === 'unaffected').map(v => v?.version?.replace(/['"]+/g, '') || '');
            
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
async function getScanId(params) {
    try {
        const db = new Client({
            user: DB_USER,
            host: DB_HOST,
            database: DB_NAME,
            password: DB_PASSWORD,
            port: DB_PORT,
        });

        await db.connect();
        
        const result = await db.query(`
            SELECT scan_id 
            FROM vulnerabilities 
            ORDER BY created_at DESC 
            LIMIT 1
        `);

        await db.end();

        if (result.rows.length > 0) {
            return result.rows[0].scan_id;
        }
        return null;

    } catch (error) {
        console.error('Error getting scan ID:', error);
        throw error;
    }
}
async function insertData(vulnerabilityRecords) {
    const db = new Client({
        user: DB_USER,
        host: DB_HOST,
        database: DB_NAME,
        password: DB_PASSWORD,
        port: DB_PORT,
      });

    try {
      // Connect to PostgreSQL
      await db.connect();
      for (const record of vulnerabilityRecords) {
        await db.query(`
          INSERT INTO vulnerabilities (
          id, 
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

export { processVulnerabilityData, insertData };
// async function main() {
//     const data = await scan();
//     // console.log('Scan results:', JSON.stringify(data, null, 2));
//     const vulnerabilityRecords = await  processVulnerabilityData(data);
//     // console.log("Vulnerability Records:", vulnerabilityRecords);
//     await insertData(vulnerabilityRecords);
// }

// main().catch(error => console.error('Main error:', error));