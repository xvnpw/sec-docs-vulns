- Vulnerability name: Cross-Site Scripting (XSS) in Web UI via Unsafe SARIF Rendering
- Description:
  1. An attacker crafts a malicious static analysis result (e.g., a modified Pysa output).
  2. This malicious result contains JavaScript code embedded within issue messages, callable names, filenames, or other fields that are displayed in the web UI.
  3. The SAPP backend processes this malicious result and stores it in the database.
  4. When a user accesses the SAPP web UI and views the analysis results, the backend serves data from the database.
  5. The web UI, without proper sanitization, renders the malicious JavaScript code embedded in the data.
  6. The user's browser executes the malicious JavaScript code, leading to XSS.
- Impact:
  - Execution of arbitrary JavaScript code in the user's browser.
  - Session hijacking, cookie theft, redirection to malicious sites, defacement of the UI, and other malicious actions.
- Vulnerability rank: high
- Currently implemented mitigations: None evident from provided files.
- Missing mitigations:
  - Input sanitization on the backend before storing data in the database.
  - Output encoding/escaping in the frontend when rendering data from the database, especially in React components.
  - Content Security Policy (CSP) to restrict the capabilities of the browser and mitigate the impact of XSS.
- Preconditions:
  - An attacker needs to be able to provide malicious static analysis results to SAPP. This might involve:
    - Modifying static analysis output files before processing them with SAPP.
    - If SAPP integrates with a static analysis service, compromising that service to inject malicious results.
- Source code analysis:
  - File: /code/sapp/sarif.py
    - The `issue_to_sarif` and `trace_to_sarif` methods construct SARIF JSON structure from issue data, including fields like `message`, `filename`, etc.
    - There is no explicit sanitization of these fields before including them in the SARIF output. This means if the underlying issue data contains malicious content, it will be directly included in the SARIF JSON.
    - The `SARIFEncoder` then converts this data into a JSON string, which is served by the backend.
- Security test case:
  1. Prepare a malicious Pysa output file (`taint-output-xss.json`) with the following content:
```json
{
  "version": 1,
  "codes": {},
  "filenames": [],
  "issues": [
    {
      "code": 5001,
      "message": "<img src=x onerror=alert('XSS Vulnerability')>",
      "location": { "path": "vuln.py", "line": 1, "start": 1, "end": 1 },
      "sink": "...",
      "source": "..."
    }
  ]
}
```
  2. Run SAPP to analyze this malicious output: `sapp --database-name sapp-xss.db analyze taint-output-xss.json`
  3. Start the SAPP web server: `sapp --database-name sapp-xss.db server --source-directory=./code`
  4. Access the SAPP web UI in a browser (e.g., http://localhost:13337).
  5. Navigate to the list of issues and locate the issue from `taint-output-xss.json`.
  6. Click on the issue to view its details.
  7. Observe if an alert box with "XSS Vulnerability" appears. If it does, the XSS vulnerability is confirmed.