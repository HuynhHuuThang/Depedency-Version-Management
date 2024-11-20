document.addEventListener('DOMContentLoaded', () => {
    fetchVulnerabilities();
});

async function fetchVulnerabilities() {
    try {
        const response = await fetch('http://localhost:3000/api/vulnerabilities/latest');
        const data = await response.json();
        
        if (data.length > 0) {
            const tbody = document.getElementById('vulnerabilitiesBody');
            tbody.innerHTML = '';
            
            data.forEach((vuln, index) => {
                // Define severity class for badge
                const severityClass = getSeverityClass(vuln.severity);
                
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td>${index + 1}</td>
                    <td>${vuln.id}</td>
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