- Vulnerability Name: Unhandled Zero-Dimension GeoJSON leading to Division by Zero

- Description:
  1. An attacker provides a GeoJSON file to the `supermercado burn` command that represents a zero-dimensional geometry (e.g., a POINT, or a LINESTRING with identical start and end points) or a geometry that, after projection and tile processing, results in a tile range with zero width or height.
  2. The `find_extrema` function calculates the bounding box of the GeoJSON features.
  3. The `tile_extrema` function determines the tile range based on the calculated bounding box. For a zero-dimension geometry or specific edge cases, it's possible that `tilerange["x"]["max"]` becomes equal to `tilerange["x"]["min"]` (or similarly for 'y').
  4. In the `make_transform` function, when calculating the affine transformation parameters, a division by zero error occurs in either the x-cell or y-cell calculation: `xcell = (lrx - ulx) / float(tilerange["x"]["max"] - tilerange["x"]["min"])` or `ycell = (uly - lry) / float(tilerange["y"]["max"] - tilerange["y"]["min"])`.
  5. This `ZeroDivisionError` is not caught, causing the `supermercado burn` command to terminate abruptly with a traceback, disrupting the intended operation.

- Impact:
  The `supermercado burn` command crashes, leading to a service disruption. While not arbitrary code execution, it prevents the tool from processing valid GeoJSON data in scenarios involving zero-dimension or edge-case geometries, effectively acting as a denial of service for this specific functionality.

- Vulnerability Rank: Medium

- Currently Implemented Mitigations:
  None. The code lacks specific input validation to handle zero-dimension geometries or error handling for potential division by zero in the affine transformation calculation.

- Missing Mitigations:
  - Implement input validation within the `burn` command or its helper functions to detect and gracefully handle zero-dimension geometries or geometries that result in zero-width or zero-height tile ranges. This could involve checking the output of `find_extrema` or `tile_extrema` before proceeding to `make_transform`.
  - Incorporate error handling in the `make_transform` function to catch potential `ZeroDivisionError`. Instead of crashing, the function should return an error indicator or raise a custom exception that is handled higher up in the call stack, allowing for a user-friendly error message to be displayed and preventing program termination.

- Preconditions:
  - The attacker must be able to supply arbitrary GeoJSON input to the `supermercado burn` command. This is typically the case when the tool is used in a context where users can upload or specify GeoJSON data to be processed.

- Source Code Analysis:
  - **File: `/code/supermercado/burntiles.py` - `make_transform` function:**
    ```python
    def make_transform(tilerange, zoom):
        ulx, uly = mercantile.xy(
            *mercantile.ul(tilerange["x"]["min"], tilerange["y"]["min"], zoom)
        )
        lrx, lry = mercantile.xy(
            *mercantile.ul(tilerange["x"]["max"], tilerange["y"]["max"], zoom)
        )
        xcell = (lrx - ulx) / float(tilerange["x"]["max"] - tilerange["x"]["min"]) # Potential division by zero
        ycell = (uly - lry) / float(tilerange["y"]["max"] - tilerange["y"]["min"]) # Potential division by zero
        return Affine(xcell, 0, ulx, 0, -ycell, uly)
    ```
    The `make_transform` function calculates `xcell` and `ycell` by dividing by the difference in tile range dimensions. If the tile range has zero width (`tilerange["x"]["max"] - tilerange["x"]["min"] == 0`) or zero height (`tilerange["y"]["max"] - tilerange["y"]["min"] == 0`), a `ZeroDivisionError` will occur. This scenario can arise when processing GeoJSON inputs that result in a bounding box with zero width or height after tile range calculation.

- Security Test Case:
  1. Create a GeoJSON file named `point.geojson` with a Point feature. This represents a zero-dimensional geometry:
     ```json
     {"type": "FeatureCollection", "features": [{"type": "Feature", "properties": {}, "geometry": {"type": "Point", "coordinates": [0, 0]}}]}
     ```
  2. Open a terminal and execute the `supermercado burn` command, piping the content of `point.geojson` as input and specifying a zoom level (e.g., 10):
     ```bash
     cat point.geojson | supermercado burn 10
     ```
  3. Observe the output. The `supermercado burn` command will crash and display a traceback that includes a `ZeroDivisionError` originating from the `make_transform` function in `/code/supermercado/burntiles.py`. This confirms the vulnerability as the application fails to gracefully handle the zero-dimension GeoJSON input and terminates unexpectedly due to the division by zero error.