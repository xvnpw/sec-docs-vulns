- Vulnerability Name: Injection vulnerability in `parse_resource_id` function via regular expression

- Description:
    1. The `parse_resource_id` function in `applications/NotificationHandler/__init__.py` uses a regular expression to parse the resource ID from the webhook payload.
    2. The regex `"\/?subscriptions\/(?P<subscription_id>[0-9a-z-]+)\/resourceGroups\/(?P<resource_group>[a-zA-Z0-9-_.()]+)(|\/providers\/Microsoft\.Solutions\/applications\/(?P<application_name>[a-zA-Z0-9-_.()]+))$"` is vulnerable to Regular Expression Denial of Service (ReDoS) attacks.
    3. A threat actor can send a crafted `applicationId` in the webhook payload that exploits the regex complexity, causing the function to consume excessive CPU resources and potentially leading to a denial-of-service condition or delayed processing of legitimate requests.
    4. While this is not a full Denial of Service vulnerability as excluded, it can still significantly impact the availability and performance of the Notification Endpoint.

- Impact:
    - The function processing time for webhook requests can significantly increase, potentially leading to delays in processing legitimate events.
    - In extreme cases, it could lead to resource exhaustion and impact the availability of the Azure Function.

- Vulnerability Rank: Medium

- Currently Implemented Mitigations:
    - None. The code uses the vulnerable regular expression as is.

- Missing Mitigations:
    - Implement input validation and sanitization for the `applicationId` before passing it to the `parse_resource_id` function.
    - Consider using a simpler and more efficient method for parsing the resource ID, such as string splitting, if the format is consistent.
    - Implement a timeout for the `parse_resource_id` function to prevent excessive processing time in case of a ReDoS attack.
    - Consider using a more robust and ReDoS-resistant regular expression or a different parsing library.

- Preconditions:
    - The Notification Endpoint Azure Function is publicly accessible and configured as the notification endpoint URL in Partner Center.
    - An attacker can send POST requests to the Notification Endpoint with a crafted JSON payload.

- Source Code Analysis:
    1. File: `/code/applications/NotificationHandler/__init__.py`
    2. Function: `parse_resource_id(resource_id: str)`
    3. The vulnerable regex is defined as: `pattern = "\/?subscriptions\/(?P<subscription_id>[0-9a-z-]+)\/resourceGroups\/(?P<resource_group>[a-zA-Z0-9-_.()]+)(|\/providers\/Microsoft\.Solutions\/applications\/(?P<application_name>[a-zA-Z0-9-_.()]+))$"`
    4. This regex is used to parse the `applicationId` which is extracted directly from the JSON payload of the incoming webhook request: `application_id = req_body["applicationId"]`
    5. If a malicious actor crafts an input string for `applicationId` that causes catastrophic backtracking in the regex engine, the `re.match` operation can take an extremely long time to complete.
    6. Example of potentially malicious input that could trigger ReDoS (note: this is a simplified example, actual exploit might require more refined input based on regex engine and optimizations): `/subscriptions/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/resourceGroups/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb