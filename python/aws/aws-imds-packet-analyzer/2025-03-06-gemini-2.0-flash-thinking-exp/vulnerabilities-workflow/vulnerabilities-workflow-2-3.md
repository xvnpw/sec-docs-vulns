### Vulnerability List

- Vulnerability Name: Incomplete Token Redaction in Logs
- Description:
    - The ImdsPacketAnalyzer tool is designed to log details of IMDS calls, including request headers and payloads. For IMDSv2 calls, these payloads may contain sensitive EC2 metadata tokens in the `X-aws-ec2-metadata-token` header.
    - The tool attempts to redact these tokens from log messages using the `hideToken` and `recurseHideToken` functions in `src/imds_snoop.py` before writing them to log files.
    - However, the current redaction logic relies on simple string matching for `x-aws-ec2-metadata-token:` and `==` to identify and redact tokens. This approach might be incomplete and could fail to redact tokens if the token format deviates slightly from the expected format, such as:
        - Different casing in the header name (e.g., `X-AWS-EC2-Metadata-Token:`).
        - Variations in whitespace around the header name or value.
        - Token values not ending with `==` (though less likely, variations might exist).
    - If redaction fails, sensitive EC2 metadata tokens could be inadvertently written to the log files in `/var/log/imds/imds-trace.log`.
    - While these log files are intended to be readable only by the root user, a successful attacker who gains root access to the EC2 instance could potentially read these logs and extract unredacted metadata tokens. This could further aid in privilege escalation or lateral movement.
- Impact:
    - Exposure of sensitive EC2 metadata tokens in log files.
    - Potential privilege escalation or lateral movement if an attacker gains root access to the instance and extracts unredacted tokens from logs.
- Vulnerability Rank: Medium
- Currently Implemented Mitigations:
    - Token redaction logic is implemented in the `hideToken` and `recurseHideToken` functions within `src/imds_snoop.py`.
    - Log files are stored in `/var/log/imds` and permissions are set to restrict access to root user only during initialization in `imds_snoop.py`.
- Missing Mitigations:
    - More robust and comprehensive token redaction logic is needed. This should include:
        - Case-insensitive matching for the header name `X-aws-ec2-metadata-token`.
        - Handling variations in whitespace around the header name and value.
        - More resilient token boundary detection that does not solely rely on `==` at the end of the token. Regular expression based redaction could be more robust.
    - Security test cases specifically designed to verify the effectiveness of token redaction under various header and token format variations.
- Preconditions:
    - The ImdsPacketAnalyzer tool is running on an EC2 instance.
    - An IMDSv2 call containing a metadata token is made and captured by the tool.
    - Logging is enabled and configured to write to `/var/log/imds/imds-trace.log`.
    - An attacker gains root access to the EC2 instance and can read the log files.
- Source Code Analysis:
    - File: `/code/src/imds_snoop.py`
    - Function: `hideToken(comms: str) -> str` and `recurseHideToken(comms: str) -> str`
    - Step-by-step analysis:
        1. The `print_imds_event` function in `imds_snoop.py` is called when an IMDS event is captured.
        2. Inside `print_imds_event`, the payload is extracted from `event.pkt[:event.pkt_size].decode()`.
        3. The `gen_log_msg` function is called to generate the log message. This message includes "Req details: " followed by the request headers and payload.
        4. The `recurseHideToken(log_msg)` function is called to redact tokens from the generated log message.
        5. Inside `recurseHideToken`, the code iteratively calls `hideToken` to find and redact tokens.
        6. Inside `hideToken`, `comms.find(EC_METADATA_TOKEN_)` searches for the header name "x-aws-ec2-metadata-token:". This search is case-sensitive.
        7. `comms.find("==", startToken)` searches for "==" starting from the position of the header name.
        8. If both the header name and "==" are found in the expected order, the substring between the header name and "==" (inclusive of "==") is replaced with "**token redacted**".
        9. The redacted log message is then logged using `logger.info` or `logger.warning`.

    - Visualization: Imagine the log message string. The `hideToken` function acts like a simple find and replace, looking for fixed strings. If the target string (token header and value) deviates even slightly, the find operation might fail, and redaction is skipped.

- Security Test Case:
    - Step 1: Setup:
        - Deploy the ImdsPacketAnalyzer tool on an EC2 instance. Ensure logging is enabled and configured to the default `/var/log/imds/imds-trace.log`.
        - Generate an IMDSv2 token using `curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 60"` and store the token value.
    - Step 2: Trigger IMDSv2 call with modified header casing:
        - Execute the following `curl` command on the EC2 instance to simulate an IMDSv2 call with a modified header casing (`X-AWS-EC2-Metadata-Token` instead of `X-aws-ec2-metadata-token`):
          ```bash
          curl -H "X-AWS-EC2-Metadata-Token: <YOUR_IMDSV2_TOKEN>" -v http://169.254.169.254/latest/meta-data/
          ```
          Replace `<YOUR_IMDSV2_TOKEN>` with the token obtained in Step 1.
    - Step 3: Analyze Logs:
        - Check the log file `/var/log/imds/imds-trace.log` for the corresponding log entry.
        - Examine the log entry to see if the `X-AWS-EC2-Metadata-Token` header and its value (the token) are redacted or if the actual token value is present in the logs.
    - Step 4: Expected Result:
        - Due to the case-sensitive nature of the current `hideToken` implementation, the token redaction is expected to **fail** when the header casing is altered.
        - The log file should contain the **unredacted** IMDSv2 token, demonstrating the vulnerability.
    - Step 5: Remediation Verification (After implementing mitigation - e.g., case-insensitive redaction):
        - Repeat steps 1-3 after implementing a case-insensitive redaction fix.
        - Expected Result after fix: The log file should contain the redacted token (e.g., "**token redacted**"), confirming that the mitigation is effective.