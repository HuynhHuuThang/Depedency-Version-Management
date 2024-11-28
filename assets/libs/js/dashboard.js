document.addEventListener('DOMContentLoaded', () => {
    fetchTotalVulnerabilities();
    fetchVulnerabilities();
    fetchTotalUnmanagedPackage();
    fetchCriticalVulnerability();
    fetchTotalManagedPackage();
});
async function fetchTotalVulnerabilities() {
    try {
        const response = await fetch('http://localhost:3000/api/vulnerabilities/total');
        const data = await response.json();
        const totalVulnerabilities = document.getElementById('totalVulnerabilities');
        totalVulnerabilities.innerHTML = `<h1 class="mb-1">${data.total}</h1>`;
    } catch (error) {
        console.error('Error fetching total vulnerabilities:', error);
        const totalVulnerabilities = document.getElementById('totalVulnerabilities');
        totalVulnerabilities.innerHTML = 'Error';
    }
}
async function fetchCriticalVulnerability() {
    try{
        const response = await fetch('http://localhost:3000/api/vulnerabilities/critical');
        const data = await response.json;
        const totalCritical = document.getElementById('totalCritical');
        totalCritical.innerHTML=`<h1 class="mb-1">${data.total}</h1>`;
    } catch (error) {
        console.error('Error fetching total Critical Vunerabilities: ', error);
        const totalCritical = document.getElementById('totalCritical');
        totalCritical.innerHTML = 'Error';
    }
}
async function fetchTotalUnmanagedPackage() {
    try {
        const response = await fetch('http://localhost:3000/api/dependency-scan/unmanaged/total');
        const data = await response.json();
        const totalUnmanaged = document.getElementById('totalUnmanaged');
        totalUnmanaged.innerHTML = `<h1 class="mb-1">${data.total}</h1>`;
    } catch (error) {
        console.error('Error fetching total unmanaged packages:', error);
        const totalUnmanaged = document.getElementById('totalUnmanaged');
        totalUnmanaged.innerHTML = 'Error';
    }
}
async function fetchTotalManagedPackage(){
    try {
        const response = await fetch('http://localhost:3000/api/dependency-scan/managed/total');
        const data = await response.json();
        const totalManaged = document.getElementById('totalManaged');
        totalManaged.innerHTML = `<h1 class="mb-1">${data.total}</h1>`;
    } catch (error) {
        console.error('Error fetching total managed packages:', error);
        const totalManaged = document.getElementById('totalManaged');
        totalManaged.innerHTML = 'Error';
    }
}
async function fetchVulnerabilities() {
    try {
        const response = await fetch('http://localhost:3000/api/vulnerabilities/latest');
        const data = await response.json();
        
        if (data.length > 0) {
            const tbody = document.getElementById('vulnerabilitiesDashboard');
            tbody.innerHTML = '';
            
            data.forEach((vuln, index) => {
                // Define severity class for badge
                const severityClass = getSeverityClass(vuln.severity);
                
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td>${index + 1}</td>
                    <td>${vuln.cve_id}</td>
                    <td>${vuln.package_url}</td>
                    <td>${vuln.affected_version}</td>
                    <td>
                        <span class="badge-dot ${severityClass} mr-1"></span>
                        ${vuln.severity}
                    </td>
                    <td>${vuln.cvss_score}</td>
                    <td>${vuln.fix_version}</td>
                    <td>${vuln.recommendation}</td>
                    <td>${vuln.insights}</td>
                `;
                tbody.appendChild(row);
            });
        }
    } catch (error) {
        console.error('Error fetching vulnerabilities:', error);
        const tbody = document.getElementById('vulnerabilitiesBody');
        tbody.innerHTML = `
            <tr>
                <td colspan="9" class="text-center">
                    Error loading vulnerability data. Please try again later.
                </td>
            </tr>
        `;
    }
}

function getSeverityClass(severity) {
    switch (severity.toLowerCase()) {
        case 'critical':
        case 'high':
            return 'badge-danger';
        case 'medium':
            return 'badge-warning';
        case 'low':
            return 'badge-success';
        default:
            return 'badge-info';
    }
}