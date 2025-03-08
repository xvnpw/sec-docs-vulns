- Vulnerability Name: Cross-Site Scripting (XSS) via Log Injection in User-Agent and Referer Fields

- Description:
    1. An attacker crafts malicious log entries containing Javascript code within the User-Agent or Referer fields of web server logs.
    2. These crafted log entries are then imported into Matomo using the `import_logs.py` script.
    3. Matomo stores and displays these log entries within its analytics dashboard, typically in reports like "Visitors > Overview" or "Acquisition > Referrers".
    4. When a Matomo user views these reports through their web browser, the malicious Javascript code injected into the User-Agent or Referer fields is executed within the user's browser session. This occurs because Matomo does not properly sanitize or encode these fields when displaying them in the dashboard.

- Impact:
    - **Account Takeover:** An attacker could potentially steal the session cookies of Matomo users who view the affected reports. This could lead to the attacker gaining unauthorized access to the Matomo account, potentially with administrative privileges, allowing them to control the analytics data, modify configurations, or even further compromise the Matomo instance.
    - **Data Theft:** Malicious Javascript could be designed to extract sensitive data from the Matomo dashboard, such as analytics data, user information, or configuration details, and send it to an attacker-controlled server.
    - **Redirection to Malicious Sites:** The injected script could redirect Matomo users to attacker-controlled websites, potentially for phishing attacks or malware distribution.
    - **Defacement of Matomo Dashboard:** The attacker could alter the appearance or functionality of the Matomo dashboard for all users, causing disruption and loss of trust in the analytics data.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
    - None. The `import_logs.py` script imports log data and sends it to Matomo without any explicit sanitization or encoding of the User-Agent or Referer fields that would prevent XSS. The code directly forwards the extracted values to Matomo's tracking API without modification.

- Missing Mitigations:
    - **Input Sanitization/Encoding:** The `import_logs.py` script should sanitize or encode the User-Agent and Referer fields before sending data to Matomo. Specifically, HTML encoding should be applied to these fields to prevent Javascript code from being executed in the browser. This sanitization should be implemented within the `_get_hit_args` function in the `Recorder` class, before the data is sent to the Matomo API.
    - **Content Security Policy (CSP) in Matomo:** Although not a mitigation in `import_logs.py` itself, implementing a strong Content Security Policy within the Matomo application would provide a defense-in-depth measure against XSS attacks, including those originating from log injection. CSP can restrict the sources from which Javascript and other dynamic content can be loaded, mitigating the impact of injected malicious scripts.

- Preconditions:
    1. The attacker needs to be able to inject log entries into the web server logs that are processed by `import_logs.py`. This is often achievable in shared hosting environments or when attackers have compromised systems that generate logs ingested by Matomo.
    2. Matomo must be configured to display reports that include User-Agent or Referer data. This is the default configuration for many Matomo reports.
    3. A Matomo user with access to view the affected reports must access the Matomo dashboard through their web browser after the malicious logs have been imported.

- Source Code Analysis:
    1. **Log Parsing:** The `import_logs.py` script parses web server logs using regular expressions or predefined formats. The `FORMATS` dictionary in `import_logs.py` defines various log formats and their corresponding regular expressions. For example, the `ncsa_extended` format regex includes groups for 'referrer' and 'user_agent': `r'\s+"(?P<referrer>.*?)"\s+"(?P<user_agent>.*?)"`.
    2. **Data Extraction:** The `RegexFormat` class and its subclasses extract data from log lines based on these regular expressions. The `get()` method retrieves the captured groups, such as User-Agent and Referer, directly from the regex match.
    3. **Hit Construction:** The `Parser` class processes each log line and creates a `Hit` object. The `parse()` method in the `Parser` class extracts the 'referrer' and 'user_agent' values using `format.get('referrer')` and `format.get('user_agent')` and assigns them to the `Hit` object.
    4. **Data Forwarding to Matomo:** The `Recorder` class takes the `Hit` objects and prepares them for sending to the Matomo API in the `_get_hit_args()` method.  Crucially, the `_get_hit_args()` function in `Recorder` class takes the `hit.referrer` and `hit.user_agent` values **directly** and includes them in the parameters sent to the Matomo tracking API without any sanitization or encoding.
    ```python
    def _get_hit_args(self, hit):
        # ...
        args = {
            'rec': '1',
            'apiv': '1',
            'url': url,
            'urlref': hit.referrer[:1024], # hit.referrer is directly used
            'cip': hit.ip,
            'cdt': self.date_to_matomo(hit.date),
            'idsite': site_id,
            'queuedtracking': '0',
            'dp': '0' if config.options.reverse_dns else '1',
            'ua': hit.user_agent # hit.user_agent is directly used
        }
        # ...
        return UrlHelper.convert_array_args(args)
    ```
    5. **No Sanitization:** There is no code in `import_logs.py` that sanitizes or encodes the `hit.referrer` or `hit.user_agent` before they are included in the `args` dictionary and sent to Matomo.
    6. **Matomo Display:** Matomo's backend stores the raw User-Agent and Referer strings in its database. When these values are retrieved and displayed in the Matomo dashboard, the Javascript code is executed by the user's browser because Matomo's frontend also lacks sufficient output encoding for these fields in all contexts.

- Security Test Case:
    1. **Prerequisites:**
        -  A running Matomo instance accessible via a web browser.
        -  The `matomo-log-analytics` tool installed and configured to import logs into the Matomo instance.
        -  Web server logs that `import_logs.py` can process (e.g., Apache or Nginx access logs).
        -  A user account in Matomo with permissions to view visitor reports (e.g., 'view' access to a website).
    2. **Craft Malicious Log Entry:** Create a log entry with a malicious Javascript payload in the User-Agent field. For example, for an NCSA Extended Log Format, a line could look like this:
    ```log
    1.2.3.4 - - [31/Dec/2024:12:00:00 +0000] "GET /index.html HTTP/1.1" 200 123 "-" "<script>alert('XSS Vulnerability')</script>"
    ```
    3. **Inject Malicious Log Entry:** Append this crafted log entry to your web server's access log file.
    4. **Import Logs into Matomo:** Run the `import_logs.py` script to import the modified log file into your Matomo instance, using the appropriate command-line arguments for your Matomo setup and log file path (e.g., `./import_logs.py --url=your_matomo_url --token-auth=your_token /path/to/your/access.log`).
    5. **Access Matomo Dashboard:** Log in to your Matomo instance using a web browser with your test user account.
    6. **Navigate to Visitor Reports:** Go to a Matomo report that displays User-Agent information, such as "Visitors > Overview" or "Visitors > User Agent".
    7. **Observe XSS:** Check if the Javascript code injected in the User-Agent field is executed when the report is loaded. You should see an alert box with the message "XSS Vulnerability" if the test is successful. If using a different payload, observe the intended behavior of the injected Javascript (e.g., redirection, data exfiltration).
    8. **Verify in Referrer Report (Optional):** Repeat steps 2-7, but inject the malicious Javascript into the Referer field instead of the User-Agent field and check reports that display Referrer information, such as "Acquisition > Referrers".