- Vulnerability Name: Unauthenticated HTTP Proxy Usage in VM Extensions
- Description:
  1. The Azure Linux Agent supports using an HTTP proxy defined by environment variables (`http_proxy`, `https_proxy`) or configuration variables (`HttpProxy.Host`, `HttpProxy.Port`).
  2. The agent passes these proxy settings to VM Extensions.
  3. The agent documentation explicitly states that "the agent *does not* support HTTP proxies requiring authentication."
  4. If an attacker can control the environment variables or manipulate the agent's configuration (preconditions), they can force VM Extensions to use a malicious proxy.
  5. This malicious proxy can intercept and potentially modify requests made by VM Extensions, including sensitive data being transmitted by extensions.
  6. Step by step trigger:
     - Attacker gains control or influence over the VM's environment variables (e.g., through a separate vulnerability or misconfiguration).
     - Attacker sets `http_proxy` or `https_proxy` to point to their malicious proxy server.
     - A VM Extension, configured to use the proxy settings from the agent, makes an HTTP/HTTPS request.
     - The request is routed through the attacker's proxy server, allowing interception and potential modification of the request and response.
- Impact:
  - Information Disclosure: Sensitive data transmitted by VM Extensions can be intercepted by the malicious proxy.
  - Data Manipulation: An attacker could potentially modify requests or responses, leading to unexpected behavior or security breaches within the VM.
  - Privilege Escalation (potentially): Depending on the extension's functionality and the attacker's ability to manipulate requests, this could potentially lead to privilege escalation within the VM.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
  - None specific to authentication for proxies. The documentation only warns against using authenticated proxies.
- Missing Mitigations:
  - Implement support for authenticated HTTP proxies.
  - Provide clear guidance and warnings in documentation against using unauthenticated proxies, especially in production environments.
  - Consider restricting the usage of proxy settings within extensions or providing a mechanism for extensions to securely configure their proxy settings, independent of the agent's configuration.
- Preconditions:
  - Attacker's ability to set environment variables within the VM or modify the agent's configuration file `/etc/waagent.conf`.
  - VM Extensions are configured to use the agent's proxy settings (this is the default behavior).
- Source Code Analysis:
  - The `README.md` file documents the HTTP Proxy functionality and explicitly mentions the lack of authentication support:
    ```markdown
    ### HTTP Proxy
    The Agent will use an HTTP proxy if provided via the `http_proxy` (for `http` requests) or
    `https_proxy` (for `https` requests) environment variables. Due to limitations of Python,
    the agent *does not* support HTTP proxies requiring authentication.
    ...
    The Agent passes its environment to the VM Extensions it executes, including `http_proxy` and `https_proxy`, so defining
    a proxy for the Agent will also define it for the VM Extensions.
    ```
  - The code itself (Python) would need to be analyzed to confirm how proxy settings are handled and passed to extensions, but the documentation clearly states the vulnerability. Based on the provided files `exthandlers.py` and `cgroupconfigurator.py`, there's no indication of changes or mitigations for this vulnerability. The files are primarily focused on extension lifecycle management and cgroup configuration, respectively.
- Security Test Case:
  1. Set up a malicious HTTP proxy server that logs all requests and responses.
  2. On an Azure VM running the Linux Agent, set the environment variable `http_proxy` (or `https_proxy`) to point to the malicious proxy server's address. This can be done by modifying the Agent's service configuration (e.g., `/etc/systemd/system/walinuxagent.service.d/http-proxy.conf` on systemd-based systems).
  3. Deploy a VM Extension that makes an HTTP/HTTPS request (any extension making network calls will suffice; a simple test extension could be created for this purpose).
  4. Observe the logs of the malicious proxy server to confirm that the VM Extension's request was routed through it.
  5. (Optional) Modify the malicious proxy to alter the response from the intended destination and observe the behavior of the VM Extension to verify data manipulation is possible.