document.addEventListener('DOMContentLoaded', function() {
    const submitBtn = document.getElementById('submitBtn');
    const directoryPathInput = document.getElementById('directoryPath');

    submitBtn.addEventListener('click', async function(e) {
        e.preventDefault();
        console.log('Button clicked!');
        const path = directoryPathInput.value;
        
        if (!path) {
            console.error('Please enter a valid directory path');
            return;
        }

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
            
            const data = await response.json();
            console.log('Scan results:', data);
        } catch (error) {
            console.error('Error during scan:', error);
            alert('Error during scan. Please check the console for details.');
        }
    });
});
