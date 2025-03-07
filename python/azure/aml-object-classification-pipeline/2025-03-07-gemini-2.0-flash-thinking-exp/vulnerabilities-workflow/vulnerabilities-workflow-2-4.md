- vulnerability name: Server-Side Request Forgery (SSRF) in test-endpoint.py
- description:
    - The `test-endpoint.py` script takes an image URL as a command-line argument (`--image_url`).
    - It uses `urllib.request.urlopen(image_url)` to fetch the image from the provided URL.
    - The script then converts the image to base64 and sends it to the deployed Azure Machine Learning endpoint for object classification.
    - If an attacker provides a malicious URL instead of a legitimate image URL, the `urllib.request.urlopen` function will attempt to access the resource at that URL from the server hosting the Azure Machine Learning endpoint.
    - This could allow an attacker to perform a Server-Side Request Forgery (SSRF) attack.
    - For example, an attacker could provide a URL pointing to internal services within the Azure environment or to the metadata endpoint of the Azure instance.
- impact:
    - An attacker could potentially gain access to internal resources or sensitive information accessible to the Azure Machine Learning endpoint.
    - In the context of Azure, this could include accessing the instance metadata service to retrieve sensitive information like credentials, configuration details, or access tokens.
    - An attacker might be able to probe internal network infrastructure, potentially identifying and interacting with other internal services that are not intended to be publicly accessible.
- vulnerability rank: high
- currently implemented mitigations:
    - There are no input validation or sanitization mechanisms implemented in `test-endpoint.py` to prevent SSRF. The script directly uses the user-provided URL without any checks.
- missing mitigations:
    - Input validation and sanitization for the `image_url` parameter in `test-endpoint.py` is missing.
    - A whitelist of allowed URL schemes (e.g., only `http://` and `https://`) and hostnames could be implemented.
    - URL parsing and validation to prevent access to internal IP ranges or restricted hostnames should be added.
    - Consider using a dedicated library for URL handling and validation to avoid common pitfalls.
- preconditions:
    - The Azure Machine Learning pipeline must be deployed and the web service endpoint must be publicly accessible.
    - An attacker needs to know or guess the scoring URI of the deployed web service. This information might be obtained through reconnaissance or by observing network traffic if the endpoint is used.
- source code analysis:
    - File: `/code/test-endpoint.py`
    ```python
    import urllib.request
    # ... other imports ...
    import argparse

    # Define arguments
    parser = argparse.ArgumentParser(description='Test script parser')
    parser.add_argument('--image_url', type=str, help='URL of the image to score', default='https://compote.slate.com/images/222e0b84-f164-4fb1-90e7-d20bc27acd8c.jpg')
    image_url = parser.parse_args().image_url # [VULNERABLE CODE] User-provided URL is directly assigned

    # ... get scoring url ...

    # Download image and convert to base 64
    with urllib.request.urlopen(image_url) as url: # [VULNERABLE CODE] URL is used without validation
        test_img = io.BytesIO(url.read())

    # ... rest of the code ...
    ```
    - The vulnerability lies in the direct usage of the `image_url` variable, which is derived from user input, within `urllib.request.urlopen()`.
    - No validation or sanitization is performed on `image_url` before making the request.
    - An attacker can control the `image_url` parameter and make the server-side application send requests to arbitrary URLs.
- security test case:
    - Precondition: Deploy the Azure Machine Learning pipeline and obtain the scoring URI of the deployed web service.
    - Step 1: Prepare a malicious URL. For testing SSRF on Azure, a common target is the instance metadata endpoint: `http://169.254.169.254/metadata/instance?api-version=2021-08-01`. This endpoint, when accessed from within an Azure VM, reveals instance metadata, potentially including sensitive information.
    - Step 2: Execute the `test-endpoint.py` script, providing the malicious URL as the `--image_url` argument:
    ```bash
    python test-endpoint.py --image_url http://169.254.169.254/metadata/instance?api-version=2021-08-01
    ```
    - Step 3: Observe the output and server-side logs (if accessible).
    - Expected Outcome:
        - If the vulnerability is present, the `urllib.request.urlopen` call will attempt to access the metadata endpoint from the server hosting the deployed service.
        - The response from the metadata endpoint (which could contain sensitive instance information) might be visible in the logs of the Azure Machine Learning endpoint, or indirectly observable through error messages if the response is not properly handled when it's not an image.
        - Even if the raw response is not directly returned to the attacker in the standard output, an indication of successful SSRF would be observing delays or errors related to accessing the internal metadata service, or observing network requests originating from the service's IP address to the internal IP `169.254.169.254` in server-side network logs (if available).
        - Note: Direct reflection of the metadata content in the standard output might not be guaranteed due to how the script processes the fetched content. However, the SSRF vulnerability is confirmed if the service attempts to access the internal URL, which can be verified through network monitoring or error behavior.