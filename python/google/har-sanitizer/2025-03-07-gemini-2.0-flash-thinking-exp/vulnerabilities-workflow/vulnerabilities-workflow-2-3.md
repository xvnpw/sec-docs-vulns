- Vulnerability Name: HAR Parameter Injection leading to Sanitization Bypass
- Description:
    1. An attacker crafts a malicious HAR file.
    2. This HAR file contains a crafted entry with a `request` object.
    3. Inside the `request` object, the attacker injects a parameter within `queryString` or `params` array that has a `name` field designed to interfere with the sanitization logic. For example, an attacker can inject a parameter with `name` set to `"__proto__"` or `"constructor"` or similar JavaScript prototype pollution or object property manipulation keywords.
    4. When the `/scrub_har` endpoint processes this HAR file, the `iter_eval_exec` function in `HarSanitizer` might be vulnerable to property reassignment or unexpected behavior due to the injected parameter name.
    5. This could potentially bypass the intended sanitization logic by modifying internal states of the `Har` or `HarSanitizer` objects, leading to sensitive data not being redacted.
- Impact:
    - Sensitive information from the HAR file, intended to be sanitized, may be exposed.
    - Attackers can potentially exfiltrate passwords, cookies, headers, or other private data contained within the HAR file by bypassing sanitization.
    - In a worst-case scenario, depending on how the injected parameter is processed, it might be possible to cause unexpected behavior or errors in the server-side application.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - The code uses decorators `@accept("application/json")` and `@require("application/json")` for the `/scrub_har` endpoint in `harsan_api.py`, ensuring that the API only accepts and requires JSON data. This mitigates against some types of basic injection attacks that rely on different content types.
    - The `Har` class in `harsanitizer.py` performs basic validation to ensure the input is a valid HAR structure during initialization in `load_har` function, which raises `ValueError` for invalid HAR formats. This prevents the API from crashing with completely malformed input.
- Missing Mitigations:
    - Input sanitization and validation are insufficient. The application lacks specific checks to validate the `name` fields within the `queryString` and `params` arrays of the HAR file to prevent injection of potentially harmful parameter names like JavaScript prototype properties or internal object keywords.
    - There is no explicit input validation within the `iter_eval_exec` function in `harsanitizer.py` to prevent manipulation via crafted keys in the HAR data. The code relies on `eval(cond)` for conditional checks, but does not validate the keys and values being processed to avoid logic bypasses.
- Preconditions:
    - The attacker needs to be able to craft a HAR file and send it to the `/scrub_har` endpoint of the Flask API.
    - The Flask API instance of the HAR sanitizer must be publicly accessible or accessible to the attacker.
- Source Code Analysis:
    1. **`harsanitizer.py` - `HarSanitizer.iter_eval_exec` function:**
        ```python
        def iter_eval_exec(self, my_iter, cond_table):
            if isinstance(my_iter, dict):
              for key, value in my_iter.iteritems():
                # Makes it run faster, even though it seems counterintuitive
                if any([eval(cond) for cond in cond_table.keys()]): # [POINT OF CONCERN] - eval usage and key processing
                  for cond, callback in cond_table.iteritems():
                    # Security risks have been mitigated by
                    # preventing any possible code-injection
                    # attempt into cond_table keys
                    if eval(cond): # [POINT OF CONCERN] - eval usage and condition evaluation
                      callback(self, my_iter, key, value) # [POINT OF CONCERN] - callback execution with potentially manipulated key/value
                elif isinstance(value, (dict, list)):
                  self.iter_eval_exec(
                      value,
                      cond_table)
            elif isinstance(my_iter, list):
              for value in my_iter:
                self.iter_eval_exec(
                    value,
                    cond_table)

            return my_iter
        ```
        - The `iter_eval_exec` function iterates through the HAR dictionary structure.
        - It uses `eval(cond)` to evaluate conditions defined in `cond_table.keys()`. While the comment mentions mitigation against code injection in `cond_table` keys, the code itself doesn't perform validation on the `key` and `value` variables extracted from the HAR data during iteration.
        - If an attacker can control the `key` value in the HAR structure (e.g., by injecting a parameter name like `__proto__` in `queryString`), and a condition in `cond_table` relies on this `key`, the `eval(cond)` might lead to unintended behavior or allow for logic bypass. For example, if a condition is `"key == 'cookie'"` and an attacker injects a parameter with `name` as `"cookie"` within `queryString`, this condition would evaluate to true even if the context is not actually a cookie object, potentially leading to misapplication of sanitization logic.
        - The callback function `callback(self, my_iter, key, value)` is executed if `eval(cond)` is true. If the `key` or `value` has been manipulated, the callback might operate on unintended data or in an unintended way.

    2. **`harsanitizer.py` - `HarSanitizer.gen_hartype_names_pattern` function:**
        ```python
        def gen_hartype_names_pattern(self, har, hartype):
            # ...
            def outer_callback(self, my_iter, key, value):
              def inner_callback(self, my_iter, key, value):
                if value in har.category[hartype]:
                  har.category[hartype][value] += 1
                else:
                  har.category[hartype][value] = 1

              self.iter_eval_exec(
                  value,
                  {"key == 'name'": inner_callback} # [POINT OF CONCERN] - Condition relies on 'name' key from HAR, which is attacker-controlled.
              )

            har.category[hartype] = {}

            cond_table = {
                "key == '{}'".format(hartype): outer_callback # [POINT OF CONCERN] - Condition relies on hartype, but iteration context is not strictly validated.
            }

            return cond_table
        ```
        - This function generates conditions to extract names of different HAR types (cookies, headers, params).
        - Both `outer_callback` and `inner_callback` rely on conditions based on `key` values from the HAR structure (`key == '{}'".format(hartype)` and `"key == 'name'"`). If an attacker can inject parameters with `name` that matches these conditions, the logic might be misled.
        - For instance, if `hartype` is 'queryString', and an attacker injects a parameter with `name` set to 'queryString', the `outer_callback` might be triggered in unintended contexts during the iteration process.

- Security Test Case:
    1. **Setup:** Run the Flask API locally or use a publicly available instance.
    2. **Craft Malicious HAR:** Create a HAR file (e.g., `malicious.har`) with the following structure. This HAR file injects a parameter with `name` set to `__proto__` within the `queryString`.
        ```json
        {
          "log": {
            "entries": [
              {
                "request": {
                  "queryString": [
                    {
                      "name": "__proto__",
                      "value": "injected_value"
                    },
                    {
                      "name": "sensitive_param",
                      "value": "sensitive_value_to_exfiltrate"
                    }
                  ],
                  "url": "http://example.com/api/resource?sensitive_param=sensitive_value_to_exfiltrate"
                },
                "response": {
                  "content": {
                    "mimeType": "text/plain",
                    "text": "This is a response with sensitive data: sensitive_response_data"
                  }
                }
              }
            ]
          }
        }
        ```
    3. **Send Malicious HAR to `/scrub_har`:** Use `curl` or `requests` to send a POST request to the `/scrub_har` endpoint with the crafted `malicious.har` file as JSON data.
        ```bash
        curl -X POST -H "Content-Type: application/json" -d @malicious.har http://localhost:8080/scrub_har > scrubbed_har.json
        ```
    4. **Analyze Scrubbed HAR:** Examine the `scrubbed_har.json` file. Check if the `sensitive_param` value (`sensitive_value_to_exfiltrate` in `queryString` and in URL) and `sensitive_response_data` within the `content.text` are properly redacted.
    5. **Expected vs. Actual Result:**
        - **Expected (Sanitization Works):** Both `sensitive_param` and `sensitive_response_data` should be redacted in the output `scrubbed_har.json`.
        - **Actual (Vulnerability Exists):** If the vulnerability is successfully exploited, the sanitization logic might be bypassed or weakened due to the injected `__proto__` parameter, and `sensitive_param` or `sensitive_response_data` might **not** be fully redacted in `scrubbed_har.json`, or the sanitization might be incomplete or exhibit unexpected behavior. Specifically, check if "sensitive_value_to_exfiltrate" or "sensitive_response_data" is still present in the scrubbed HAR.