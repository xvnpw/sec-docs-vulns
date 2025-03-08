- Vulnerability Name: Server-Side Request Forgery (SSRF)
- Description:
    1. An attacker can provide a malicious URL as the `PATH` argument to the `rio glui` command-line tool.
    2. The `rio-glui` application, running on the server, will take this URL and use the `rasterio` library to attempt to open and process the resource at that URL.
    3. If the provided URL points to an internal resource or an external service that the server should not access, the server will make a request to that resource.
    4. The response from the internal resource or external service might be exposed or used in a way that was not intended by the application, potentially leading to information disclosure or further attacks.
    5. For example, an attacker could use a URL pointing to `http://localhost/internal-admin-panel` or `http://169.254.169.254/latest/meta-data` (AWS metadata endpoint) to probe for internal services or retrieve sensitive cloud instance metadata.
- Impact:
    - Information Disclosure: Attackers might be able to access sensitive information from internal services or cloud metadata endpoints that are not intended to be publicly accessible.
    - Internal Network Scanning: Attackers can use the server to scan internal networks and identify open ports and services.
    - Access to Internal Services: Attackers might be able to interact with internal services that are not exposed to the public internet, potentially leading to further exploitation.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - None. The application directly uses user-provided URLs without any validation or sanitization.
- Missing Mitigations:
    - URL validation: Implement checks to validate that the provided PATH is a valid and expected URL.
    - URL sanitization: Sanitize the URL to prevent injection of malicious characters or unexpected paths.
    - Whitelist/Blacklist for URLs: Implement a whitelist of allowed URL schemes (e.g., `http`, `https`, `s3`) or a blacklist of disallowed URL schemes or domains to restrict the application's access to external resources.
    - Network segmentation: Isolate the `rio-glui` application server from sensitive internal networks to limit the impact of SSRF.
- Preconditions:
    - The `rio-glui` application must be running and accessible to the attacker, either publicly or within a network the attacker has access to.
    - The attacker needs to know or guess URLs of internal resources or services that might be accessible from the server running `rio-glui`.
- Source Code Analysis:
    1. File: `rio_glui/scripts/cli.py`
    2. Function: `glui`
    3. The `path` argument is taken directly from the command line input:
       ```python
       @click.command()
       @click.argument("path", type=str)
       def glui(path, ...):
           ...
           raster = RasterTiles(path, indexes=bidx, tiles_size=tiles_dimensions, nodata=nodata)
           ...
       ```
    4. File: `rio_glui/raster.py`
    5. Class: `RasterTiles`
    6. Constructor: `__init__`
    7. The `src_path` argument, which is directly derived from the command-line `path`, is passed to `rasterio.open()` without any validation:
       ```python
       class RasterTiles(object):
           def __init__(self, src_path, indexes=None, tiles_size=512, nodata=None):
               self.path = src_path
               with rasterio.open(src_path) as src: # Vulnerable line: rasterio.open() opens URLs without validation
                   ...
       ```
    8. The `rasterio.open(src_path)` function is known to accept URLs as input, and in this code, there is no check to ensure that `src_path` is a safe or expected URL. This allows an attacker to control the URL that the server-side application will request.
- Security Test Case:
    1. Pre-requisite: Deploy `rio-glui` application on a server accessible to the attacker. Assume the server has access to `http://localhost:8080` (the same port where `rio-glui` runs, for simplicity of demonstration - in real scenario this could be any internal service).
    2. Attacker crafts a malicious URL: `http://localhost:8080/index.html`. This URL points back to the `rio-glui` application itself, but it could be any internal service.
    3. Attacker executes the `rio glui` command with the malicious URL as the `PATH` argument:
       ```sh
       rio glui http://localhost:8080/index.html
       ```
    4. Observe the server-side application's behavior. Using network monitoring tools (like `tcpdump` on the server or server-side logs if available), verify that the server makes an HTTP request to `http://localhost:8080/index.html`.
    5. If the server successfully fetches the content of `http://localhost:8080/index.html` and attempts to process it as a GeoTIFF (which will likely fail as HTML is not a GeoTIFF), this confirms that the SSRF vulnerability exists. A successful fetch of internal content, even if it causes an error later in the `rio-glui` process, demonstrates the SSRF vulnerability.
    6. In a more realistic scenario, the attacker would try to access URLs of actual internal services or cloud metadata endpoints to check for sensitive information or further attack vectors. For example, trying to access `http://169.254.169.254/latest/meta-data` on an AWS instance.