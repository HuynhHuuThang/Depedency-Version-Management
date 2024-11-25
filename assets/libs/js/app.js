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
        // await saveToScanResult(data);
        // await saveToDev(data);
        return data;
    } catch (error) {
        console.error('Error during scan:', error);
        alert('Error during scan. Please check the console for details.');
        throw error;
    }
}

async function saveToScanResult(data) {
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
        console.log('Data successfully saved to the database.');
    } catch (error) {
        console.error('Error saving data to the database:', error);
        throw error;
    }
}


async function saveToDev(data) {
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
        console.log('Data successfully saved to the database.');
    } catch (error) {
        console.error('Error saving data to the database:', error);
        throw error;
    }
}
