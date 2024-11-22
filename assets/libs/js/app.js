// app.js

export async function scan(path) {
    console.log('Scanning path:', path);
    try {
        const response = await fetch('http://localhost:3000/proxy-scan', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                path: path,
                type: "nodejs",
                profile: "generic"
            })
        });
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        const data = await response.json();
        console.log('Scan results:', data);
        const processedData = processVulnerabilityData(data);
        console.log('Processed data:', processedData);
        return data;
    } catch (error) {
        console.error('Error during scan:', error);
        alert('Error during scan. Please check the console for details.');
        throw error;
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