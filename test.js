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
        const fs = require('fs');
        fs.writeFileSync('scan-results.json', JSON.stringify(data, null, 2));
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
    console.log("Received data:", data);
    
    // Check if data and vulnerabilities exist
    if (!data || !data.vulnerabilities) {
        console.log("No vulnerability data found");
        return vulnerabilityRecords;
    }
    
    for (const vuln of data.vulnerabilities) {
        try {
            // Get the vulnerability ID
            const vulnId = Array.isArray(vuln.id) ? vuln.id[0] : vuln.id;
            console.log("Processing vulnerability:", vulnId);
            
            // Get rating information with safe access
            const ratings = Array.isArray(vuln.ratings) ? vuln.ratings : [];
            const rating = ratings[0] || {};
            
            // Get affected version info with safe access
            const affects = Array.isArray(vuln.affects) ? vuln.affects : [];
            const affect = affects[0] || {};
            const versions = affect.versions || [];
            
            // Find insights with safe access
            const properties = Array.isArray(vuln.properties) ? vuln.properties : [];
            const insightsProp = properties.find(p => p?.name === 'depscan:insights');
            const insights = insightsProp?.value || '';
            
            const record = {
                vulnerability_id: vulnId || '',
                score: rating.score || null,
                severity: rating.severity || null,
                description: (vuln.description || '')
                    .replace(/\\n/g, ' ')
                    .replace(/\\/g, '')
                    .trim(),
                recommendation: vuln.recommendation || '',
                affected_package: affect.ref || '',
                affected_versions: versions.map(v => ({
                    version: v?.version || '',
                    status: v?.status || ''
                })),
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
    //             INSERT INTO vulnerabilities (
    //                 vulnerability_id,
    //                 score,
    //                 severity,
    //                 description,
    //                 recommendation,
    //                 affected_package,
    //                 affected_versions,
    //                 insights
    //             ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
    //         `, [
    //             record.vulnerability_id,
    //             record.score,
    //             record.severity,
    //             record.description,
    //             record.recommendation,
    //             record.affected_package,
    //             JSON.stringify(record.affected_versions), // Store versions as JSON
    //             record.insights
    //         ]);
    //     }
    //     console.log(`Successfully processed ${vulnerabilityRecords.length} vulnerabilities`);
    // } catch (error) {
    //     console.error('Error inserting vulnerability records:', error);
    //     throw error;
    // }
    console.log(`Processed ${vulnerabilityRecords.length} vulnerability records`);
    return vulnerabilityRecords;
}

async function main() {
    const data = await scanDependencies();
    console.log('Scan results:', JSON.stringify(data, null, 2));
    await processVulnerabilityData(data);
}

main().catch(error => console.error('Main error:', error));