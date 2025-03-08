### Vulnerability List

- Vulnerability Name: Property Key Overwrite via `gather_properties`
- Description:
    1. A malicious GeoJSON file is crafted with a Feature that includes keys outside of the standard GeoJSON Feature keys (like `type`, `geometry`, `properties`, `id`).
    2. One of these extra keys is intentionally named to be identical to an existing key within the `properties` object of the same Feature.
    3. The `geojson-quirks` tool is executed with the `--gather-properties` option, targeting this malicious GeoJSON file.
    4. The `tweak_feature` function within `geojson-quirks/tweak.py` is invoked to process the Feature.
    5. The `gather_properties` logic in `tweak_feature` identifies the non-standard keys and prepares to move them into the `properties` object.
    6. The code uses `feature['properties'].update(new_properties)` to merge these gathered properties. Python's `dict.update()` overwrites existing keys if a key from `new_properties` already exists in `feature['properties']`.
    7. Consequently, the value of the property in the `properties` object is replaced by the value of the identically named extra key from the Feature, effectively allowing an attacker to overwrite existing property values.
- Impact:
    - Data Integrity: Legitimate property values within the GeoJSON Feature can be maliciously overwritten.
    - Application Logic Bypass: If downstream applications depend on the integrity of specific property values, this overwrite can lead to unexpected behavior, errors, or security vulnerabilities in those applications.
- Vulnerability Rank: Medium
- Currently Implemented Mitigations: None
- Missing Mitigations:
    - Implement a check for key collisions when gathering properties. If a collision is detected between an external key and an existing property key, the tool should either:
        - Rename the gathered property to avoid overwriting (e.g., prefix the external key with `_external_` or similar).
        - Issue a warning to the user, indicating that property keys are being overwritten and giving them the option to proceed or halt.
- Preconditions:
    - The user must execute `geojson-quirks` with the `--gather-properties` command-line option.
    - The input GeoJSON file must contain a Feature object.
    - This Feature object must have:
        - At least one key that is not a standard GeoJSON Feature key (`type`, `geometry`, `properties`, `id`).
        - At least one of these non-standard keys must have the same name as a key that is already present within the Feature's `properties` object.
- Source Code Analysis:
    - File: `/code/geojson_quirks/tweak.py`
    - Function: `tweak_feature`
    - Vulnerable code block:
      ```python
      if gather_properties:
          new_properties = {}
          del_properties = []
          for k, v in feature.items():
              if k not in native_feature_keys:
                  new_properties[k] = v
                  del_properties.append(k)
          feature['properties'].update(new_properties) # Vulnerable line: dict.update overwrites existing keys
          for p in del_properties:
              del feature[p]
      ```
    - The vulnerability occurs in the line `feature['properties'].update(new_properties)`. When `dict.update()` is used, keys from `new_properties` that are already present in `feature['properties']` will have their values overwritten by the values from `new_properties`. In this context, if a non-standard key from the Feature (which is being moved to properties) has the same name as an existing key in `feature['properties']`, the original property value will be overwritten.
- Security Test Case:
    1. Create a file named `malicious.geojson` with the following JSON content:
       ```json
       {
         "type": "FeatureCollection",
         "features": [
           {
             "type": "Feature",
             "properties": {
               "existing_property": "original_value"
             },
             "geometry": {
               "type": "Point",
               "coordinates": [0, 0]
             },
             "existing_property": "malicious_value",
             "extra_property": "extra_value"
           }
         ]
       }
       ```
    2. Execute the `geojson-quirks` tool from the command line with the `--gather-properties` option, processing the `malicious.geojson` file and redirecting the output to `output.geojson`:
       ```bash
       geojson-quirks --gather-properties malicious.geojson > output.geojson
       ```
    3. Examine the contents of the `output.geojson` file. Verify that within the `properties` object of the Feature, the value of `existing_property` has been changed from `"original_value"` to `"malicious_value"`. This confirms that the extra key `existing_property` from the Feature has overwritten the property with the same name.
       ```json
       {
         "type": "FeatureCollection",
         "features": [
           {
             "type": "Feature",
             "properties": {
               "existing_property": "malicious_value",  // Value overwritten
               "extra_property": "extra_value"
             },
             "geometry": {
               "type": "Point",
               "coordinates": [0, 0]
             }
           }
         ]
       }