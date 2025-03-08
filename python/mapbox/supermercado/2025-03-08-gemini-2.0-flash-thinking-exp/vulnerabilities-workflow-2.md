### Vulnerability List

- Vulnerability Name: GeoJSON Processing Vulnerability in `rasterio.features.rasterize` via Malicious Polygon

    - Description:
        1. The `supermercado burn` command processes GeoJSON features to generate tiles, using `rasterio.features.rasterize` to convert polygons into raster representations.
        2. An attacker provides a crafted GeoJSON file with a complex or malformed polygon (e.g., self-intersections, many vertices) to the `supermercado burn` command.
        3. `rasterio.features.rasterize` processes this malicious polygon, potentially triggering vulnerabilities in `rasterio` or its underlying libraries (GDAL, GEOS, shapely).
        4. This can lead to excessive resource consumption, program crash (DoS), or potentially arbitrary code execution if memory corruption occurs in rasterization libraries.

    - Impact:
        High. Successful exploitation can cause denial of service through resource exhaustion or program termination. In a worst-case scenario, it could lead to arbitrary code execution on the server due to memory corruption in rasterization libraries.

    - Vulnerability Rank: High

    - Currently Implemented Mitigations:
        None. No input validation or sanitization is performed on GeoJSON geometries before processing by `rasterio.features.rasterize`. The `filter_features` function only filters by geometry type, not geometry validity or complexity.

    - Missing Mitigations:
        - Implement input validation and sanitization for GeoJSON geometries before using `rasterio.features.rasterize`.
        - Validate geometric validity using libraries like `shapely` to ensure polygons conform to GeoJSON standards (e.g., no self-intersections, correct ring orientation).
        - Limit geometry complexity by imposing restrictions on the number of vertices in polygons and overall geometry complexity to prevent excessive processing and DoS.
        - Validate coordinate ranges to prevent numerical issues in rasterization libraries.

    - Preconditions:
        The attacker must be able to supply a GeoJSON file or stream as input to the `supermercado burn` command. This is possible if the `supermercado burn` command is exposed to external users, such as through a web service or command-line interface.

    - Source Code Analysis:
        - **File: `supermercado/scripts/cli.py` - `burn` command:**
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
            The `burn` command takes GeoJSON input via `@cligj.features_in_arg`, which is then filtered by `super_utils.filter_features` for geometry type only. The features are then passed to `burntiles.burn`.

        - **File: `supermercado/burntiles.py` - `burn` function:**
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
            The `burn` function directly utilizes `rasterio.features.rasterize` to process geometries from the input `polys` (GeoJSON features) without any validation of the geometry's structure or complexity. The `project_geom` function performs projection but does not validate the geometry itself.

        - **Data Flow Visualization:**
            ```
            [GeoJSON Input] --> cligj.features_in_arg --> [features] --> super_utils.filter_features (type filter only) --> [filtered_features] --> burntiles.burn --> rasterio.features.rasterize([geometries]) --> [rasterized output]
            ```
            This flow shows that GeoJSON input is parsed and passed to `rasterio.features.rasterize` with minimal processing and no geometry content validation.

    - Security Test Case:
        1. Create a GeoJSON file named `malicious.geojson` with a FeatureCollection containing a single Feature with a Polygon geometry. This polygon should be highly complex, for example, by including a very large number of vertices or self-intersections.
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
        2. Execute the `supermercado burn` command in a terminal, providing `malicious.geojson` as input and specifying a zoom level (e.g., 9):
            ```bash
            cat malicious.geojson | supermercado burn 9
            ```
        3. Observe the system's resource usage (CPU, memory) and the execution time of the `supermercado burn` command.
        4. Expected Outcome (Vulnerable): The `supermercado burn` command will consume excessive resources (CPU and memory) and may take an extremely long time to process or crash due to issues within `rasterio.features.rasterize` when handling the complex polygon.
        5. Expected Outcome (Mitigated): The command should process the input within reasonable resource limits and time, or reject the input with an informative error message if the geometry is deemed too complex or invalid.