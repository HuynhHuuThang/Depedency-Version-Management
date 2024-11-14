import { spawn } from 'child_process';
function runPythonScript(directoryPath, scriptArgs) {
    // Using Node.js child_process to execute Python script
    
    
    // Specify the Python script path relative to the directory
    const pythonScript = 'cli.py'; // Change this to your script name
    
    try {
        // Combine script path with additional arguments
        const args = [pythonScript, ...scriptArgs];
        
        // Spawn Python process with arguments
        const pythonProcess = spawn('python', args, {
            cwd: directoryPath // Set working directory
        });

        // Handle stdout data
        pythonProcess.stdout.on('data', (data) => {
            console.log(`Python Output: ${data}`);
        });

        // Handle stderr data
        pythonProcess.stderr.on('data', (data) => {
            console.error(`Error: ${data}`);
        });

        // Handle process completion
        pythonProcess.on('close', (code) => {
            if (code !== 0) {
                console.log(`Python script exited with code ${code}`);
            } else {
                console.log('Python script completed successfully');
            }
        });

    } catch (error) {
        console.error('Failed to run Python script:', error);
    }
}

runPythonScript('E:\Semester6\IndividualProject\Project\dep-scan-5.4.8\depscan', '-h');
