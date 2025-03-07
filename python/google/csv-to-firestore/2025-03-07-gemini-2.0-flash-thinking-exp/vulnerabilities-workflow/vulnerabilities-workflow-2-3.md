### Vulnerability List:

#### 1. Firestore Collection Injection via Filename Parameter Manipulation
* **Description:**
    1. An attacker crafts a malicious CSV filename.
    2. This filename includes the `collection` parameter, but with a value pointing to an unintended Firestore collection. For example, a malicious filename could be `malicious_data[collection=attacker_collection].csv` instead of `data[collection=intended_collection].csv`.
    3. The attacker uploads this malicious CSV file to the Cloud Storage bucket that triggers the Cloud Function.
    4. The `csv_to_firestore_trigger` function is executed upon file upload.
    5. Inside `csv_to_firestore_trigger`, the `get_parameters_from_filename` function parses the filename.
    6. `get_parameters_from_filename` extracts the `collection_id` from the filename using regular expressions, specifically from the `collection` parameter. In our example, it extracts `attacker_collection`.
    7. The extracted `collection_id` (`attacker_collection` in our example) is passed to the `csv_to_firestore` function without any validation.
    8. The `csv_to_firestore` function uses this attacker-controlled `collection_id` to construct the Firestore collection path.
    9. Consequently, the data from the uploaded CSV file is written to the attacker-specified Firestore collection (`attacker_collection`), instead of the intended collection.

* **Impact:**
    * **Data Integrity Violation:** Data is written to unintended Firestore collections. This can lead to the corruption or overwriting of data in collections that were not meant to receive this specific CSV data.
    * **Unauthorized Data Modification:** Attackers can modify data in arbitrary Firestore collections if they know or guess collection names.
    * **Potential Confidentiality Breach:** If sensitive data is stored in other Firestore collections, an attacker might be able to inject data into these collections, potentially gaining unauthorized access or insight into the data or even exfiltrating existing data by overwriting it with attacker-controlled content and triggering other processes based on changes in Firestore.

* **Vulnerability Rank:** High

* **Currently Implemented Mitigations:**
    * None. The application relies solely on filename parsing to determine the Firestore collection, without any validation or sanitization of the extracted collection ID.

* **Missing Mitigations:**
    * **Input Validation and Sanitization:** Implement validation for the `collection_id` extracted from the filename. This should include:
        * **Whitelist Approach:** Define a whitelist of allowed Firestore collection IDs. The application should only accept collection IDs that are present in this whitelist.
        * **Regular Expression Validation:** Implement a more restrictive regular expression to parse the collection ID, ensuring it conforms to expected patterns and does not contain potentially malicious characters or sequences.
        * **Input Sanitization:** Sanitize the extracted `collection_id` to remove any potentially harmful characters or escape sequences before using it to construct the Firestore collection path.

* **Preconditions:**
    * The Cloud Function is deployed and configured to trigger on CSV file uploads to a Cloud Storage bucket.
    * An attacker has the ability to upload files to the configured Cloud Storage bucket. This could be through public write access (if misconfigured) or through compromised credentials with write access to the bucket.

* **Source Code Analysis:**
    1. **`python/main.py:69 - csv_to_firestore_trigger(event, context)`**: The function `csv_to_firestore_trigger` is the entry point, triggered by file uploads. It calls `get_parameters_from_filename(event['name'])` to parse the filename and extract parameters.
    ```python
    def csv_to_firestore_trigger(event, context):
      firestore_path = get_parameters_from_filename(event['name'])
      storage_client, db = storage.Client(), firestore.Client()
      csv_to_firestore(event, storage_client, db, firestore_path)
    ```
    2. **`python/main.py:142 - get_parameters_from_filename(filename)`**: This function extracts the `collection_id` by calling `regex_search_string(filename, 'collection')`.
    ```python
    def get_parameters_from_filename(filename):
      collection_id = regex_search_string(filename, 'collection')
      document_id = regex_search_string(filename, 'key')
      if collection_id is None:
        raise ValueError(...)
      return {
              "collection_id": collection_id,
              "document_id": document_id
              }
    ```
    3. **`python/main.py:157 - regex_search_string(filename, parameter)`**: This function uses a regular expression to find and extract the value of the specified parameter from the filename. The regex `r'\[' + parameter + r'=(.*?)\]'` captures any characters between `[` and `]` after `parameter=`. The extracted value is then returned after removing the brackets and parameter name.
    ```python
    def regex_search_string(filename, parameter):
      out = re.search(r'\[' + parameter + r'=(.*?)\]', filename)
      if out is None:
        return None
      return out.group().replace('[' + parameter + '=', '').replace(']', '')
    ```
    **Visualization:**

    ```
    Filename (attacker controlled): malicious_file[collection=attacker_collection].csv
        |
        v
    get_parameters_from_filename()
        |
        v
    regex_search_string(filename, 'collection')
        |
        v
    Regex: r'\[collection=(.*?)\]'  matches 'collection=attacker_collection' and captures 'attacker_collection'
        |
        v
    Returns: collection_id = 'attacker_collection' (Unvalidated)
        |
        v
    csv_to_firestore() uses collection_id to write to Firestore collection 'attacker_collection'
    ```

* **Security Test Case:**
    1. **Prerequisites:**
        * Deploy the Cloud Function as described in the `README.md`.
        * Identify the Cloud Storage bucket that triggers the Cloud Function (YOUR_TRIGGER_BUCKET_NAME).
        * Have access to upload files to this bucket.
    2. **Steps:**
        * Create a CSV file named `malicious_data[collection=attacker-collection].csv` with some sample data. The `attacker-collection` is the malicious collection name we want to inject.
        ```csv
        id,name
        1,test_data_1
        2,test_data_2
        ```
        * Upload `malicious_data[collection=attacker-collection].csv` to the Cloud Storage bucket that triggers the Cloud Function (YOUR_TRIGGER_BUCKET_NAME).
        * Wait for the Cloud Function to execute (check Cloud Function logs for execution confirmation).
        * In the Firebase console, navigate to Firestore.
        * Check if a new collection named `attacker-collection` has been created.
        * Verify that the data from `malicious_data[collection=attacker-collection].csv` has been written to the `attacker-collection` Firestore collection.
    3. **Expected Result:**
        * A new Firestore collection named `attacker-collection` is created (if it didn't exist before).
        * The data from the uploaded CSV file is present in the `attacker-collection` Firestore collection.
        * This confirms that the attacker successfully injected the collection ID and wrote data to an unintended Firestore collection.