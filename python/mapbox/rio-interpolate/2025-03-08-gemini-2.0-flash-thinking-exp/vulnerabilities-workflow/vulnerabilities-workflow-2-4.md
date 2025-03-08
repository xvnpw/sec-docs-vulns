### Vulnerability List:

- Vulnerability Name: KeyError due to missing GeoJSON keys
- Description:
  1. The `rio-interpolate` tool parses GeoJSON input to extract geometry coordinates.
  2. The functions `getBounds` and `parseLine` in `rio_interpolate/__init__.py` directly access dictionary keys 'geometry' and 'coordinates' of the GeoJSON features without checking if these keys exist.
  3. If a GeoJSON input is provided with a feature that is missing the 'geometry' key or the 'coordinates' key within the 'geometry' dictionary, a `KeyError` exception will be raised.
  4. This will cause the program to terminate unexpectedly.
- Impact:
  - Program termination: The `rio-interpolate` tool will crash and stop processing the input GeoJSON.
  - Denial of Service (minor): An attacker can cause the tool to fail by providing a crafted GeoJSON, disrupting its intended functionality.
  - Information Disclosure (minor): Error messages might reveal internal code structure or paths, although in this case, it's likely to be a standard Python `KeyError` traceback.
- Vulnerability Rank: medium
- Currently Implemented Mitigations:
  - `filterBadJSON` function handles JSON parsing errors but does not validate the structure of the parsed JSON objects beyond being valid JSON.
- Missing Mitigations:
  - Input validation: Before accessing 'geometry' and 'coordinates' keys, the code should check if these keys exist in the GeoJSON feature.
  - Error handling: Instead of directly crashing on `KeyError`, the application should gracefully handle the error, possibly by logging a warning and skipping the invalid feature or exiting with a user-friendly error message.
- Preconditions:
  - The attacker needs to provide a crafted GeoJSON file or input stream to `rio-interpolate`.
  - The crafted GeoJSON must contain at least one feature that is missing either the 'geometry' key or the 'coordinates' key within the 'geometry' dictionary.
- Source Code Analysis:
  - File: `rio_interpolate/__init__.py`
  - Function: `getBounds(features)` and `parseLine(feat)`
  - Vulnerable Code Snippet in `getBounds`:
    ```python
    xy = np.vstack(list(f['geometry']['coordinates'] for f in features))
    ```
    If any feature `f` in `features` does not have the key 'geometry' or if `f['geometry']` does not have the key 'coordinates', a `KeyError` will be raised when trying to access `f['geometry']['coordinates']`.
  - Vulnerable Code Snippet in `parseLine`:
    ```python
    return np.array(feat['geometry']['coordinates'])
    ```
    Similarly, if `feat` does not have the key 'geometry' or if `feat['geometry']` does not have the key 'coordinates', a `KeyError` will be raised.
- Security Test Case:
  1. Create a malicious GeoJSON file named `malicious.geojson` with the following content, which is missing the 'geometry' key:
     ```json
     {"type": "FeatureCollection",
      "features": [
        {"type": "Feature",
         "properties": {},
         "no_geometry": {"type": "LineString", "coordinates": [[0, 0], [1, 1]]}}
      ]}
     ```
  2. Run the `rio-interpolate` command with the malicious GeoJSON file and a sample raster file (you can use any valid raster file for testing, or create a dummy one if necessary). Assume `sample.tif` is a valid raster file in the current directory.
     ```bash
     fio cat malicious.geojson | rio interpolate sample.tif
     ```
  3. Observe the output. The program should crash with a `KeyError` traceback, indicating the vulnerability.