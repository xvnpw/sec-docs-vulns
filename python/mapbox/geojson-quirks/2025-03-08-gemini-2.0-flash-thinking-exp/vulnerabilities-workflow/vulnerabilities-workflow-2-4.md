- Vulnerability Name: GeoJSON Property Flattening Key Collision
- Description:
  1. User executes the `geojson-quirks` command-line tool with the `--flatten` option.
  2. User provides a GeoJSON FeatureCollection or Feature as input, where Feature properties contain nested dictionaries.
  3. Within these nested properties, there exists a combination of keys that, when flattened using underscore `_` as a separator, results in a key that already exists at the top level of the properties dictionary.
  4. The `_flatten` function in `geojson_quirks/tweak.py` processes the properties. When a flattened key duplicates an existing top-level key, the value of the original key is overwritten by the value from the nested dictionary.
- Impact:
  Data integrity is compromised. The flattening process can unintentionally overwrite existing properties with values from nested properties due to key collisions. This can lead to data loss or corruption, and misrepresentation of the intended data.
- Vulnerability Rank: Medium
- Currently Implemented Mitigations: None
- Missing Mitigations:
  - Implement key collision detection before or during the flattening process.
  - If key collisions are detected, implement a strategy to handle them, such as:
    - Automatically rename the colliding keys by adding a suffix or prefix to ensure uniqueness.
    - Issue a warning or error message to the user, informing them about the key collision and potential data loss.
    - Provide an option for users to define a custom separator or collision resolution strategy.
- Preconditions:
  - The user must utilize the `--flatten` option when running `geojson-quirks`.
  - The input GeoJSON data must contain Feature properties with nested dictionaries that can produce key collisions upon flattening.
- Source Code Analysis:
  - The vulnerability lies within the `_flatten` function in `/code/geojson_quirks/tweak.py`:
    ```python
    def _flatten(d, parent_key='', sep='_'):
        items = []
        for k, v in d.items():
            new_key = parent_key + sep + k if parent_key else k
            if isinstance(v, collections.MutableMapping):
                items.extend(_flatten(v, new_key, sep=sep).items())
            else:
                items.append((new_key, v))
        return dict(items)
    ```
    - The line `new_key = parent_key + sep + k if parent_key else k` constructs the flattened key by concatenating the `parent_key`, the separator `sep` (which is `_`), and the current key `k`.
    - If this generated `new_key` is identical to an already existing key in the top-level properties dictionary, the subsequent update of `feature['properties']` with the flattened dictionary will result in overwriting the original value associated with that key.
- Security Test Case:
  1. Create a file named `collision.geojson` with the following GeoJSON content:
     ```json
     {
         "type": "FeatureCollection",
         "features": [
             {
                 "type": "Feature",
                 "properties": {
                     "a": 1,
                     "b": {"c": 2},
                     "b_c": 3
                 },
                 "geometry": {"type": "Point", "coordinates": [0, 0]}
             }
         ]
     }
     ```
  2. Execute the `geojson-quirks` tool from the command line with the `--flatten` option, using `collision.geojson` as input and redirecting the output to `output.geojson`:
     ```bash
     geojson-quirks --flatten collision.geojson > output.geojson
     ```
  3. Examine the `output.geojson` file. The `properties` of the Feature in the output should be:
     ```json
     "properties": {
         "a": 1,
         "b_c": 2
     }
     ```
     - Observe that the original property `"b_c": 3` has been overwritten by the flattened value from the nested property `b.c`, which became `"b_c": 2` after flattening, demonstrating the key collision and data overwrite vulnerability.