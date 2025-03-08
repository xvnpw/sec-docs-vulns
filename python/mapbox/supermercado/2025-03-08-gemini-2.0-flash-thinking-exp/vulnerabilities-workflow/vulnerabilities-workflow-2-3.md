### Vulnerability List

- Vulnerability Name: GeoJSON Processing Vulnerability in `rasterio.features.rasterize` via Malicious Polygon

- Description:
    - The `supermercado burn` command processes GeoJSON features to generate tiles. It utilizes the `rasterio.features.rasterize` function to convert GeoJSON geometries, specifically polygons, into a raster representation for tile generation.
    - A malicious attacker can provide a specially crafted GeoJSON file containing a polygon with an excessively complex or malformed geometry (e.g., self-intersections, very large number of vertices, or other invalid geometric constructions) as input to the `supermercado burn` command.
    - When `rasterio.features.rasterize` processes this malicious polygon, it may trigger a vulnerability within `rasterio` or its underlying libraries (like GDAL, GEOS, or shapely) during the rasterization process.
    - This vulnerability could potentially lead to unexpected behavior such as excessive resource consumption, program crash, or in more severe cases, arbitrary code execution if a memory corruption vulnerability is triggered within the rasterization library.

- Impact:
    - High. Successful exploitation could lead to denial of service due to excessive resource consumption or program termination. In a worst-case scenario, if a memory corruption vulnerability is present in the underlying rasterization libraries, it could potentially lead to arbitrary code execution on the server running `supermercado`.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
    - None. The code does not perform any explicit validation or sanitization of the GeoJSON input to prevent malicious geometries from being processed by `rasterio.features.rasterize`. The `filter_features` function in `supermercado/super_utils.py` only filters based on geometry types (Polygon, Point, LineString, MultiPolygon, MultiPoint, MultiLineString) and does not perform any validation on the geometry structure or complexity.

- Missing Mitigations:
    - Input validation and sanitization for GeoJSON geometries before passing them to `rasterio.features.rasterize`. This should include checks for:
        - Geometric validity: Ensure polygons are valid according to GeoJSON and geometry standards (e.g., no self-intersections, correct ring orientation). Libraries like `shapely` can be used for geometry validation.
        - Complexity limits: Impose limits on the number of vertices in polygons or the overall complexity of geometries to prevent excessive processing and potential DoS.
        - Coordinate range validation: Ensure coordinates are within expected bounds to prevent potential numerical issues or overflows in rasterization libraries.

- Preconditions:
    - The attacker needs to be able to supply a GeoJSON file or stream as input to the `supermercado burn` command. This is possible if the `supermercado burn` command is exposed in a way that allows external users to provide input, for example, through a web service or a command-line interface accessible to external users.

- Source Code Analysis:
    - `supermercado/scripts/cli.py`:
        ```python
        @click.command("burn")
        @cligj.features_in_arg
        @cligj.sequence_opt
        @click.argument("zoom", type=int)
        def burn(features, sequence, zoom):
            """
            Burn a stream of GeoJSONs into a output stream of the tiles they intersect for a given zoom.
            """
            features = [f for f in super_utils.filter_features(features)]
            tiles = burntiles.burn(features, zoom)
            for t in tiles:
                click.echo(t.tolist())
        ```
        - The `burn` command in `cli.py` uses `@cligj.features_in_arg` to parse GeoJSON input into `features`.
        - `super_utils.filter_features(features)` is called, but it only filters feature types and doesn't validate geometry content.
        - `burntiles.burn(features, zoom)` is then called to process the features.

    - `supermercado/burntiles.py`:
        ```python
        from rasterio import features

        def burn(polys, zoom):
            # ...
            burn = features.rasterize(
                ((project_geom(geom["geometry"]), 255) for geom in polys),
                out_shape=(
                    (
                        tilerange["y"]["max"] - tilerange["y"]["min"],
                        tilerange["x"]["max"] - tilerange["x"]["min"],
                    )
                ),
                transform=afftrans,
                all_touched=True,
            )
            # ...
        ```
        - The `burn` function in `burntiles.py` directly uses `rasterio.features.rasterize` to process the geometries without any prior validation of the geometry itself.
        - The input `polys` (which are GeoJSON features) are directly passed to `rasterize` after a simple projection using `project_geom`, but no checks are performed on the validity or complexity of the geometries.

    - Visualization:
        ```
        [GeoJSON Input] --> cligj.features_in_arg --> [features] --> super_utils.filter_features --> [filtered_features] --> burntiles.burn --> rasterio.features.rasterize([geometries]) --> [rasterized output]
        ```
        - The data flow shows that GeoJSON input is parsed and then directly passed to `rasterio.features.rasterize` with minimal processing and no geometry validation.

- Security Test Case:
    - Step 1: Create a malicious GeoJSON file (e.g., `malicious.geojson`) containing a polygon with a highly complex or invalid geometry. For example, a polygon with a very large number of vertices or self-intersections. An example of a complex polygon GeoJSON structure could be:
        ```json
        {
          "type": "FeatureCollection",
          "features": [
            {
              "type": "Feature",
              "properties": {},
              "geometry": {
                "type": "Polygon",
                "coordinates": [
                  [
                    [0, 0], [1, 1], [0, 2], [1, 3], [0, 4], [1, 5], [0, 6], [1, 7], [0, 8], [1, 9],
                    [0, 0], [1, 1], [0, 2], [1, 3], [0, 4], [1, 5], [0, 6], [1, 7], [0, 8], [1, 9],
                    [0, 0], [1, 1], [0, 2], [1, 3], [0, 4], [1, 5], [0, 6], [1, 7], [0, 8], [1, 9],
                    ... (repeat many times to create a very large polygon) ...
                    [0, 0]
                  ]
                ]
              }
            }
          ]
        }
        ```
    - Step 2: Run the `supermercado burn` command with the malicious GeoJSON file as input and a zoom level (e.g., zoom level 9).
        ```bash
        cat malicious.geojson | supermercado burn 9
        ```
    - Step 3: Observe the behavior of the `supermercado burn` command.
        - Expected Vulnerable Behavior: If the vulnerability exists, the command might exhibit excessive CPU or memory usage, take an extremely long time to complete, or crash with an error due to issues in `rasterio.features.rasterize` when processing the complex polygon.
        - Expected Correct Behavior (if mitigated): The command should either process the input within reasonable resource limits and time, or reject the input with an error message indicating that the geometry is too complex or invalid.