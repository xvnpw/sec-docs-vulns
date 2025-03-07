- Vulnerability Name: Cross-Site Scripting (XSS) vulnerability in Visualization Tool

  - Description:
    1. An attacker crafts a malicious JSON data file. This file contains Javascript code within data fields, for example, in dialogue turns or intent parameters.
    2. The attacker places this malicious JSON data file in the directory served by the AirDialogue visualization tool, or tricks an administrator into visualizing it from a location the attacker controls.
    3. A user (administrator or researcher) uses the AirDialogue visualization tool, specifying the partition and index that corresponds to the malicious JSON data file.
    4. The Flask-based visualization tool reads and processes the malicious JSON data file using `json.loads`.
    5. The `generate_html` function in `airdialogue/visualizer/utils.py` and its helper functions, `generate_kv_nested_html` and `format_simple_string`, convert the JSON data into HTML. These functions use `str()` to convert JSON values to strings and embed them directly into the HTML without proper sanitization or escaping.
    6. When the visualization tool renders the generated HTML in the user's web browser, the malicious Javascript code embedded in the JSON data is executed. This is because the browser interprets the unsanitized Javascript code within the HTML context.

  - Impact:
    Successful exploitation of this XSS vulnerability allows an attacker to execute arbitrary Javascript code in the context of the user's web browser when they are using the AirDialogue visualization tool. This can lead to various malicious actions, including:
      - Stealing user's session cookies, allowing for session hijacking and account takeover.
      - Redirecting the user to malicious websites.
      - Defacing the visualization tool's webpage.
      - Performing actions on behalf of the user, such as modifying data or triggering other functionalities within the application if it has such features.
      - Gathering sensitive information displayed in the visualization tool.

  - Vulnerability Rank: High

  - Currently Implemented Mitigations:
    - There are no explicit input sanitization or output encoding mechanisms implemented in the provided code to prevent XSS in the visualization tool. The code directly converts JSON data to HTML using string conversions without any sanitization.

  - Missing Mitigations:
    - Input sanitization: The visualization tool should sanitize or validate the input JSON data to ensure it does not contain any malicious Javascript or HTML code before processing it.
    - Output encoding/escaping: When generating HTML from the JSON data, all dynamic content from the JSON should be properly HTML-encoded or escaped before being inserted into the HTML structure. This will prevent the browser from interpreting malicious scripts. Flask's templating engine (Jinja2) or dedicated libraries for HTML escaping should be used. For example, using Jinja2's automatic escaping feature would be a good mitigation.

  - Preconditions:
    1. The attacker needs to create a malicious JSON data file with embedded Javascript code.
    2. The visualization tool must be configured to read data from a directory accessible to the attacker, or the attacker must be able to convince an administrator to visualize a malicious file placed in a legitimate location.
    3. A user must access the visualization tool and request to view the malicious data (by providing the correct partition and index).

  - Source Code Analysis:
    1. File: `/code/airdialogue/visualizer/utils.py`
    2. Functions `generate_kv_nested_html` and `format_simple_string` are responsible for generating HTML from JSON data.
    3. In `format_simple_string`, the code iterates through key-value pairs and constructs strings like `key + ':' + str(el[1])`. The `str(el[1])` part converts the value to a string. This string is then directly embedded into the HTML output without any HTML encoding.
    ```python
    def format_simple_string(kv):
        sorted_list = sorted(list(kv.items()), key=lambda a: a[0])
        arr = []
        for el in sorted_list:
            key = str(el[0])
            # ... (highlighting code) ...
            arr.append((key + ':' + str(el[1]))) # Vulnerable line: str(el[1]) is directly used
        return ', '.join(arr)
    ```
    4. Similarly, `generate_kv_nested_html` uses `str(el[0])` and `str(el[1])` and embeds them into HTML table cells without encoding.
    ```python
    def generate_kv_nested_html(nested_kv, space):
        code = """<table style="width:{0}">\n""".format(space)
        for element in nested_kv:
            sorted_list = sorted(list(element.items()), key=lambda a: a[0])
            code = code + """
            <tr>
            """
            for el in sorted_list:
                code = code + '<td>' + str(el[0]) + ',' + str(el[1]) + '</td>\n' # Vulnerable line: str(el[0]) and str(el[1]) are directly used
            code = code + """
            </tr>
            """
        code += ' </table>\n'
        return code
    ```
    5. File: `/code/airdialogue/visualizer/visualizer_main.py`
    6. The `wrapper` function reads JSON data using `json.loads` and passes it to `generate_html`. The output of `generate_html` is directly returned as the response, which Flask renders as HTML.

  - Security Test Case:
    1. Create a malicious JSON file named `malicious_data.json` and `malicious_kb.json` within the data directory specified by `--data_path` when running `airdialogue vis`. For example, if `--data_path ./data/airdialogue/json/` is used, create these files in `./data/airdialogue/json/`.
    2. In `malicious_data_data.json`, put the following JSON content:
    ```json
    {"intent": {"departure_airport": "test", "return_airport": "test", "departure_month": "test", "departure_day": "test", "return_month": "test", "return_day": "test", "name": "<script>alert('XSS Vulnerability!')</script>", "departure_time": "test", "return_time": "test", "class": "test", "max_price": "test", "max_connections": "test", "airline_preference": "test", "goal": "book"}, "action": {}, "expected_action": {}, "dialogue": ["customer: Hello", "agent: Hi"]}
    ```
    3. In `malicious_data_kb.json`, put any valid KB JSON content, for example:
    ```json
    {"kb": [], "reservation": 0}
    ```
    4. Run the visualization tool: `airdialogue vis --data_path ./data/airdialogue/json/` (adjust data path if needed).
    5. Open a web browser and navigate to the URL where the visualization tool is running (e.g., http://0.0.0.0:5555/ if default host and port are used).
    6. In the visualization tool, in the "Sample #" field, enter `1`, and in the "Partition" dropdown, select `malicious_data` (or type `malicious_data` if it's not in the dropdown). Click "Submit".
    7. Observe if an alert box with the message "XSS Vulnerability!" appears in the browser. If the alert box appears, it confirms the XSS vulnerability.