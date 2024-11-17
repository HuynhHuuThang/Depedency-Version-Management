from flask import Flask, jsonify
import subprocess

app = Flask(__name__)

# Route to execute cli.py
@app.route('/run-cli', methods=['POST'])
def run_cli():
    try:
        # Run cli.py and capture output
        result = subprocess.run(['python', 'cli.py'], capture_output=True, text=True)
        return jsonify({"output": result.stdout}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(port=5000)
