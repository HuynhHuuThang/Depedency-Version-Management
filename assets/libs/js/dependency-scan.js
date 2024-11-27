import { scan } from './app.js';
import { saveToDependencyScan } from './app.js';

document.addEventListener('DOMContentLoaded', function() {
    const submitBtn = document.getElementById('submitBtn');
    const loadingOverlay = document.getElementById('loadingOverlay');
    const directoryForm = document.getElementById('directoryForm');

    submitBtn.addEventListener('click', async function(e) {
        e.preventDefault();
        const directoryPath = document.getElementById('directoryPath').value;
        
        if (!directoryPath) {
            alert('Please enter a directory path');
            return;
        }

        loadingOverlay.style.display = 'block';
        try {
            const scanResult = await scan(directoryPath);
            console.log("Dependency Scan completed successfully");
            const saveResponse = await saveToDependencyScan(scanResult);
            console.log("Dependency Scan data saved successfully");
            await fetchScanResults();
            if (saveResponse.message === 'Dependency scan data saved successfully!') {
                await fetchScanResults();
            }
        } catch (error) {
            console.error('Scan failed:', error);
        } finally {
            loadingOverlay.style.display = 'none';
        }
    });
});
document.addEventListener('DOMContentLoaded', async function() {
    await fetchScanResults(); // Automatically fetch scan results on page load
});

async function fetchScanResults() {
    try {
        const response = await fetch('http://localhost:3000/api/dependency-scan');
        const data = await response.json();
        if (data.length > 0) {
            const tbody = document.getElementById('scanResults');
            tbody.innerHTML = '';
            data.forEach((scan, index) => {
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td>${index + 1}</td>
                    <td>${scan.package_name}</td>
                    <td>${scan.current_version}</td>
                    <td>${scan.latest_version}</td>
                    <td>${scan.latest_publish_date}</td>
                    <td>${scan.weekly_downloads}</td>
                    <td>${scan.insights}</td>
                `;
                tbody.appendChild(row);
            });
        }
    } catch (error) {
        console.error('Error fetching scan results:', error);
    }
}
