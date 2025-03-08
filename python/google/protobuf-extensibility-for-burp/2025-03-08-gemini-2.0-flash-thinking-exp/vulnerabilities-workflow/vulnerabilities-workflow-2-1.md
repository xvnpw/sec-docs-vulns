### Vulnerability List:

- Vulnerability Name: Insecure Regex for Protobuf Marker Processing
- Description:
    The Burp extension uses a regular expression `marker_regex = re.escape(marker_start) + b"(.*?)" + re.escape(marker_end)` to identify and extract protobuf messages within request bodies marked by `$$`. The non-greedy quantifier `(.*?)` attempts to match the shortest possible string between the start and end markers. However, if a request body contains overlapping markers, the regex can lead to incorrect substitutions in `processHttpMessage`. Specifically, when processing a request with overlapping markers like `$$proto1$$ATTACKER_CONTROLLED_TEXT$$proto2$$`, the regex in `processHttpMessage` might incorrectly remove parts of the request body that are not intended to be protobuf messages. This happens because the regex might match from the first `$$` to the last `$$` in the overlapping sequence, treating everything in between as the protobuf content to be extracted and then replaced (effectively removed in `processHttpMessage`).
- Impact:
    An attacker can craft a malicious request with overlapping markers. When a security tester uses this Burp extension to process such a request, the regex substitution in `processHttpMessage` (`re.sub(marker_regex, b"\\1", request)`) might unintentionally remove portions of the request body. This could lead to the security tester unknowingly sending a modified request to the target application, potentially bypassing security controls, altering intended functionality, or causing unexpected application behavior. The impact is a medium severity, as it requires a security tester to be using the extension and process a specially crafted request.
- Vulnerability Rank: medium
- Currently Implemented Mitigations:
    None. The current implementation relies solely on a simple regex for marker processing without any input validation or sanitization of the content between markers.
- Missing Mitigations:
    - Input validation: Implement validation to ensure markers are correctly paired and not nested or overlapping in ways that lead to unintended parsing. A more robust parsing approach, possibly not regex-based, should be considered for handling complex marker scenarios.
    - Robust Parsing Logic: Replace the simple regex with a more sophisticated parsing logic that can correctly handle nested or overlapping markers or clearly define the expected marker structure and reject requests that deviate from it.
    - Error Handling: If marker parsing encounters issues or produces unexpected results due to malformed markers, the extension should log an error or provide a warning to the user, rather than silently modifying the request. This would alert the security tester to potential issues with the request modification.
- Preconditions:
    - The Burp extension is installed and enabled in Burp Suite.
    - Burp Suite is configured to intercept HTTP requests to a target application.
    - An attacker can influence the content of HTTP requests directed towards the target application.
    - A security tester uses the Burp extension to examine and potentially modify the crafted request within Burp Suite.
- Source Code Analysis:
    1. `proto_markers.py`:
        - `marker_start = b"$$"`
        - `marker_end = marker_start`
        - `marker_regex = re.escape(marker_start) + b"(.*?)" + re.escape(marker_end)`
        - Defines the markers and the regex used for identifying protobuf messages. The regex `(.*?)` is intended to be non-greedy, but in the context of overlapping markers, it can still lead to issues as it will match the shortest string between any start and end marker.
    2. `proto_ext.py`:
        - `processHttpMessage(self, tool_flag, is_request, message_info)`:
          ```python
          def processHttpMessage(self, tool_flag, is_request, message_info):
              if is_request:
                  request = message_info.getRequest()
                  if re.search(marker_regex, request):
                      request = re.sub(marker_regex, b"\\1", request)
                      # ... (Content-Length update logic) ...
                      message_info.setRequest(request)
          ```
          - The `processHttpMessage` function checks if the request contains markers using `re.search(marker_regex, request)`.
          - If markers are found, `re.sub(marker_regex, b"\\1", request)` is used to replace the matched marker pattern (including the markers and the content between them) with just the captured group `\1`, which corresponds to `(.*?)`. In the current logic, the intention is to remove the markers, but with overlapping markers, the regex might match a larger span than intended, leading to unintended removal of content.
          - For example, consider the request body: `$$proto1$$INJECTED_TEXT_TO_REMOVE$$proto2$$`. The regex `/\$\$(.*?)\$\$` will, in a single match, capture from the first `$$` to the last `$$` because `(.*?)` is non-greedy but still matches as much as possible to satisfy the overall pattern. Thus, in `re.sub`, the entire string `$$proto1$$INJECTED_TEXT_TO_REMOVE$$proto2$$` could be replaced with just the content between the first set of markers if the regex engine backtracks in a certain way, or, more likely depending on regex engine, it will capture `proto1$$INJECTED_TEXT_TO_REMOVE$$proto2` as group 1 and replace the whole matched string `$$proto1$$INJECTED_TEXT_TO_REMOVE$$proto2$$` with `proto1$$INJECTED_TEXT_TO_REMOVE$$proto2`, effectively removing the outer markers but not processing the intended separate protobuf messages. If the intention was to process `proto1` and `proto2` as separate protobuf messages, this approach fails and can lead to data loss or corruption in the processed request.

- Security Test Case:
    1. Prepare Burp Suite with the Protobuf extension installed and enabled.
    2. Configure Burp Suite to intercept requests to a web application (can be a local test application or a controlled web application).
    3. Craft an HTTP POST request with the following characteristics:
        - Set `Content-Type: application/octet-stream` in the headers to ensure the extension processes the request body.
        - In the request body, insert overlapping protobuf markers with attacker-controlled text in between:
          ```
          POST /test HTTP/1.1
          Host: example.com
          Content-Type: application/octet-stream
          Content-Length: [calculated length]

          Pre-marker text $$protobuf_message_1$$INJECTED_TEXT_TO_REMOVE$$protobuf_message_2$$ Post-marker text
          ```
          Replace `[calculated length]` with the actual length of the request body. `protobuf_message_1` and `protobuf_message_2` can be placeholder text or actual protobuf messages (it doesn't matter for this test case as we are testing marker processing, not protobuf decoding). `INJECTED_TEXT_TO_REMOVE` should be some unique identifiable string.
    4. Send this crafted request through Burp Suite to the target application and ensure Burp Intercept is on to examine the request after the extension processes it in `processHttpMessage`.
    5. In Burp Suite, examine the intercepted request *after* the Protobuf extension has processed it but *before* forwarding it to the server. Check the raw request body in Burp's Request editor (in the "Raw" tab of the Request viewer in Intercept or HTTP History).
    6. Verify if the `INJECTED_TEXT_TO_REMOVE` string is present or has been removed from the request body.
    7. Expected result: If the vulnerability exists, the `INJECTED_TEXT_TO_REMOVE` string will be removed from the request body in Burp's request viewer, indicating that the regex substitution in `processHttpMessage` incorrectly processed the overlapping markers and removed the unintended text. This confirms that overlapping markers can lead to unintended modification of the request body by the extension.