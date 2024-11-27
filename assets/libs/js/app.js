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
        return data;
    } catch (error) {
        console.error('Error during scan:', error);
        alert('Error during scan. Please check the console for details.');
        throw error;
    }
}

export async function saveToScanResult(data) {
    try {
        // Process the data first
        const saveResponse = await fetch('http://localhost:3000/save-final-data', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({  // Now using the processed data
                scanData: data,
            }),
        });
        if (!saveResponse.ok) {
            throw new Error(`HTTP error while saving! status: ${saveResponse.status}`);
        }
        console.log('Data successfully saved to the scan_result database.');
    } catch (error) {
        console.error('Error saving data to the scan_result database:', error);
        throw error;
    }
}


export async function saveToDev(data) {
    try {
        // Process the data first
        const saveResponse = await fetch('http://localhost:3000/save-final-data-dev', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({  // Now using the processed data
                scanData: data,
            }),
        });
        if (!saveResponse.ok) {
            throw new Error(`HTTP error while saving! status: ${saveResponse.status}`);
        }
        console.log('Data successfully saved to the dev database.');
    } catch (error) {
        console.error('Error saving data to the dev database:', error);
        throw error;
    }
}


export async function saveToDependencyScan(data) {
    try {
        const saveResponse = await fetch('http://localhost:3000/save-dependency-scan', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                scanData: data,
            }), 
        });
        if (!saveResponse.ok) {
            throw new Error(`HTTP error while saving! status: ${saveResponse.status}`);
        }
        console.log('Data successfully saved to the dependency_scan database.');
        return saveResponse;
    } catch (error) {
        console.error('Error saving data to the dependency_scan database:', error);
        throw error;
    }
}
