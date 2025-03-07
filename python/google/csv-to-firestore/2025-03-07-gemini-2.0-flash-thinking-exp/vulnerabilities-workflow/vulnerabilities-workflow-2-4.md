### Vulnerability List

#### 1. Filename Injection leading to Unintended Firestore Data Modification
* Description:
    1. An attacker uploads a CSV file to the Google Cloud Storage bucket that triggers the Cloud Function.
    2. The Cloud Function `csv_to_firestore_trigger` is automatically executed.
    3. The function `get_parameters_from_filename` parses the filename to extract the Firestore collection ID and optional document ID key column name. This extraction relies on regular expressions to find parameters within square brackets in the filename, such as `[collection=YOUR_COLLECTION_ID]`.
    4. By crafting a malicious filename, an attacker can inject an arbitrary collection ID. For example, a filename like `malicious_file[collection=attacker_collection].csv` will cause the function to interpret `attacker_collection` as the target Firestore collection ID.
    5. The `csv_to_firestore` function uses the extracted `collection_id` to write data from the uploaded CSV file into the Firestore collection specified in the malicious filename.
    6. This allows the attacker to bypass the intended collection and write data to any Firestore collection within the project, potentially leading to data corruption or unauthorized data access if collection names are guessable or predictable.
* Impact:
    * **Data Breach:** An attacker can potentially write data to Firestore collections they are not authorized to access. If collection names are predictable or guessable, this could lead to unauthorized access to sensitive data stored in those collections.
    * **Data Manipulation:** An attacker can modify or overwrite data in arbitrary Firestore collections by uploading CSV files with filenames crafted to target specific collections. This can compromise data integrity and disrupt application functionality relying on the Firestore data.
    * **Reputation Damage:** Exploitation of this vulnerability could lead to unauthorized modification of data, potentially causing damage to the reputation of the application or organization using this Cloud Function.
* Vulnerability Rank: High
* Currently Implemented Mitigations:
    * None. The code directly parses the collection ID from the filename without any validation or sanitization. The documentation describes how the filename should be structured, but this is not a security mitigation.
* Missing Mitigations:
    * **Input Validation and Sanitization:** Implement robust validation and sanitization of the extracted `collection_id` from the filename. This should include:
        * **Whitelisting:** Define a list of allowed collection IDs and only accept filenames that specify a collection ID from this whitelist.
        * **Regular Expression Validation:** Use a stricter regular expression to parse the collection ID that only allows alphanumeric characters, underscores, and hyphens, and enforces a maximum length. This can prevent injection of special characters or excessively long collection names.
        * **Sanitization:** Remove or escape any potentially harmful characters from the extracted collection ID before using it to construct the Firestore path.
    * **Access Control:** While filename-based injection bypasses intended collection selection, consider implementing additional access control layers within the Cloud Function or Firestore security rules to restrict write access to collections based on the source of the request or other contextual information, if feasible within the Cloud Function's execution context. However, for this specific trigger (Cloud Storage upload), validating the filename parameters is the most direct and effective mitigation.
* Preconditions:
    * The attacker must be able to upload files to the Google Cloud Storage bucket that triggers the Cloud Function. This could be achieved if:
        * The Cloud Storage bucket has misconfigured write permissions allowing public uploads.
        * The attacker has compromised credentials or gained access to a system that can upload files to the bucket.
        * The bucket is designed to ingest data from external sources that are under the attacker's control, allowing them to upload files with malicious filenames.
* Source Code Analysis:
    1. **`get_parameters_from_filename(filename)` function:**
       ```python
       def get_parameters_from_filename(filename):
         collection_id = regex_search_string(filename, 'collection')
         document_id = regex_search_string(filename, 'key')
         if collection_id is None:
           raise ValueError('there was no collection id specified in the filename, ',
           'try adding [collection=your_collection_id]'
           )
         return {
                 "collection_id": collection_id,
                 "document_id": document_id
                 }
       ```
       This function is responsible for extracting parameters from the filename. It calls `regex_search_string` to find the `collection` and `key` parameters. The extracted `collection_id` is directly used later to determine the Firestore collection.

    2. **`regex_search_string(filename, parameter)` function:**
       ```python
       def regex_search_string(filename, parameter):
         out = re.search(r'\[' + parameter + r'=(.*?)\]', filename)
         if out is None:
           return None
         return out.group().replace('[' + parameter + '=', '').replace(']', '')
       ```
       This function uses the regular expression `r'\[' + parameter + r'=(.*?)\]'` to find and extract the value of a given parameter within square brackets in the filename. The crucial part is `(.*?)`, which is a non-greedy wildcard that matches any character (`.`) zero or more times (`*?`). This regex is too permissive and does not validate the content of the extracted parameter. An attacker can inject arbitrary strings, including malicious collection names, into the filename, and this regex will extract them without any checks.

    3. **`csv_to_firestore(event, storage_client, db, firestore_path)` function:**
       ```python
       def csv_to_firestore(event, storage_client, db, firestore_path):
         ...
         db.collection(firestore_path['collection_id']).document(document_id)
         ...
       ```
       This function takes the `firestore_path` dictionary, which is returned by `get_parameters_from_filename`, and directly uses `firestore_path['collection_id']` to specify the target Firestore collection using `db.collection(firestore_path['collection_id'])`. Since the `collection_id` is derived directly from the potentially attacker-controlled filename without validation, this creates the filename injection vulnerability.

    **Visualization:**

    ```
    [Attacker Uploads Malicious File] --> [Cloud Storage Bucket] --> [Cloud Function Trigger] --> csv_to_firestore_trigger()
                                                                                                    |
                                                                                                    V
                                                                                              get_parameters_from_filename()
                                                                                                    | (Malicious Collection ID extracted from filename)
                                                                                                    V
                                                                                              csv_to_firestore()
                                                                                                    | (Uses malicious Collection ID)
                                                                                                    V
                                                                                          [Firestore - Unintended Collection Modified]
    ```

* Security Test Case:
    1. **Setup:**
        * Ensure you have deployed the Cloud Function to your Google Cloud Project and have the trigger bucket name.
        * Identify a Firestore project and a collection that should *not* be modified by this test (e.g., a production collection, or create a test collection that should remain untouched). Let's call this `unintended_collection`.
        * Choose or create another Firestore collection that you will intentionally write to during the test to verify the exploit (e.g., `attacker_collection`).

    2. **Create Malicious CSV File:**
        * Create a CSV file named `malicious_upload[collection=attacker_collection].csv` with the following content (or any test data):
          ```csv
          id,name
          1,Test Record 1
          2,Test Record 2
          ```

    3. **Upload Malicious File:**
        * Upload the `malicious_upload[collection=attacker_collection].csv` file to the Cloud Storage bucket that triggers the Cloud Function.

    4. **Verify Firestore:**
        * Go to the Firestore database in your Google Cloud Console.
        * Check if a new collection named `attacker_collection` has been created.
        * Verify that the documents from your malicious CSV file (e.g., documents with IDs '1' and '2' and fields 'id' and 'name') are present in the `attacker_collection`.
        * **Crucially**, check that the `unintended_collection` (the collection that should not have been modified) remains unchanged and does not contain the data from the uploaded malicious CSV file.

    5. **Expected Result:**
        * You should observe that the `attacker_collection` has been created and populated with data from the uploaded CSV file. This confirms that the filename injection was successful, and you were able to write data to a Firestore collection specified in the filename, regardless of the intended or expected collection. The `unintended_collection` should remain untouched, demonstrating the ability to redirect data flow based on filename manipulation.

This test case demonstrates how an attacker can control the destination Firestore collection by crafting a malicious filename, confirming the filename injection vulnerability.