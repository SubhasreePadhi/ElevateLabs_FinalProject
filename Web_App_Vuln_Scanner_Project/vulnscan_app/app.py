# app.py
from flask import Flask, render_template, request, redirect, url_for, session
from scanner import VulnerabilityScanner
import os

app = Flask(__name__)
# For session management (e.g., storing scan results temporarily)
# In a real application, use a strong, randomly generated key and external storage like a database.
app.secret_key = os.urandom(24) 

# Initialize scanner - keep it simple for now, a new one per request in this example
# For production, you'd want a more robust way to manage scanner instances (e.g., a queue, background tasks)

@app.route('/')
def index():
    """Renders the main page for submitting a URL to scan."""
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    """Initiates the scan based on the submitted URL."""
    target_url = request.form.get('target_url')
    scan_depth = int(request.form.get('scan_depth', 0)) # Default to 0 (current page only)

    if not target_url:
        # Handle case where no URL is provided
        return "Please provide a target URL.", 400

    if not target_url.startswith(('http://', 'https://')):
        # Ensure URL has a scheme
        target_url = "http://" + target_url

    print(f"[*] Received scan request for: {target_url} with depth {scan_depth}")

    scanner = VulnerabilityScanner()
    try:
        # Perform the scan
        scan_results = scanner.scan_url(target_url, depth=scan_depth)
        # Store results in session or a more persistent storage for larger apps
        session['scan_results'] = scan_results
        session['scanned_url'] = target_url
        return redirect(url_for('results'))
    except Exception as e:
        print(f"[-] An error occurred during scan: {e}")
        return render_template('results.html', error=f"An error occurred during scan: {e}", results=[], scanned_url=target_url)

@app.route('/results')
def results():
    """Displays the scan results."""
    results = session.pop('scan_results', []) # Get and clear results from session
    scanned_url = session.pop('scanned_url', 'N/A')
    error = session.pop('error_message', None) # Get and clear any error messages

    return render_template('results.html', results=results, scanned_url=scanned_url, error=error)

if __name__ == '__main__':
    # You might want to run this with gunicorn or similar for production
    app.run(debug=True) # debug=True for development, disable in production
