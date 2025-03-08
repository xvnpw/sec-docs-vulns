- Vulnerability Name: Server-Side Request Forgery (SSRF)
- Description:
  1. A user executes the `rio glui` command-line tool, providing a URL as the `PATH` argument instead of a local file path. For example: `rio glui http://malicious.example.com/internal/resource.tif`.
  2. The `rio glui` script passes this `PATH` argument to the `RasterTiles` class constructor in `rio_glui/raster.py`.
  3. Inside the `RasterTiles` constructor, the `rasterio.open(src_path)` function is called with the user-provided URL.
  4. `rasterio.open()` interprets the URL and attempts to make an HTTP request to `http://malicious.example.com/internal/resource.tif` from the server running `rio-glui`.
  5. If `malicious.example.com` resolves to an internal resource or an unintended external service, the server will inadvertently access it.
- Impact:
  - An attacker can potentially read sensitive data from internal services that are not meant to be publicly accessible.
  - An attacker can potentially interact with internal services, possibly leading to further vulnerabilities or misconfigurations.
  - An attacker can potentially use the server as a proxy to access external services that are otherwise blocked or monitored.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
  - None. The code directly passes the user-provided path to `rasterio.open()` without any validation or sanitization.
- Missing Mitigations:
  - Input validation and sanitization for the `PATH` argument in the `glui` command-line tool.
  - Implementation of a URL scheme whitelist to restrict allowed protocols for the `PATH` argument, permitting only safe protocols like `file://`, `http://`, `https://`, and `s3://` if intended, and explicitly disallowing others.
  - Consider validating the hostnames in URLs against a whitelist or blacklist to further control accessible destinations.
- Preconditions:
  - The `rio glui` command-line tool must be accessible to the attacker.
  - The server running `rio-glui` must have network access to internal resources or external services that the attacker wants to target.
- Source Code Analysis:
  1. In `/code/rio_glui/scripts/cli.py`, the `glui` function is defined as the entry point for the CLI tool.
  2. The `glui` function takes `path` as a command-line argument:
     ```python
     @click.command()
     @click.argument("path", type=str)
     ...
     def glui(path, ...):
         ...
         raster = RasterTiles(path, indexes=bidx, tiles_size=tiles_dimensions, nodata=nodata)
         ...
     ```
  3. The `path` argument, taken directly from user input, is passed to the `RasterTiles` constructor in `/code/rio_glui/raster.py`.
  4. In `/code/rio_glui/raster.py`, the `RasterTiles` class initializes with the provided `src_path`:
     ```python
     class RasterTiles(object):
         def __init__(self, src_path, indexes=None, tiles_size=512, nodata=None):
             self.path = src_path
             self.tiles_size = tiles_size
             with rasterio.open(src_path) as src:
                 ...
     ```
  5. The `rasterio.open(src_path)` function from the `rasterio` library is called. `rasterio.open()` is capable of opening both local file paths and URLs, as documented in the `rasterio` library documentation.
  6. If a user provides a URL as `path`, `rasterio.open()` will attempt to access and open the resource at that URL, leading to a Server-Side Request Forgery vulnerability.

- Security Test Case:
  1. Set up a simple HTTP server (e.g., using `python -m http.server 8000` in a separate terminal) that serves a file or just listens for requests. Let's say this server is on `http://localhost:8000`.
  2. Run the `rio glui` command, providing the URL to your HTTP server as the `PATH` argument: `rio glui http://localhost:8000/test.tif`.
  3. Observe the HTTP server logs. You should see a request originating from the `rio glui` process attempting to access `/test.tif`. This confirms that `rio-glui` is making an outbound request to the URL provided in the `PATH` argument.
  4. To further demonstrate SSRF to internal resources, if you have an internal service running on your network (e.g., on `http://internal.example.com/sensitive-data`), try running `rio glui http://internal.example.com/sensitive-data`. If the server running `rio-glui` has access to `internal.example.com`, the `rio glui` process will attempt to access this internal resource, potentially exposing sensitive information or functionality if `internal.example.com` is not properly secured against internal access.