### Vulnerability Report

This report summarizes identified vulnerabilities, combining information from multiple lists and removing duplicates.

#### 1. Firestore Data Injection via Malicious CSV

- **Vulnerability Name:** Firestore Data Injection via Malicious CSV
- **Description:**
    - An attacker uploads a CSV file to the designated Cloud Storage bucket.
    - The Cloud Function is triggered by the file upload.
    - The function parses the CSV file and iterates through each row.
    - For each row, the function `set_document` is called to write data to Firestore.
    - Within `set_document`, the CSV data is directly used to create Firestore documents without sanitization or validation of the data itself (only document ID is validated against Firestore constraints).
    - By crafting a malicious CSV file, an attacker can inject arbitrary data into Firestore fields, potentially overwriting existing data or inserting new, malicious data. This includes control over the values of fields within the Firestore documents.
- **Impact:**
    - Data integrity compromise: Attackers can inject or overwrite data in the Firestore database, leading to corrupted or manipulated data.
    - Potential application logic bypass: If applications rely on the integrity of the data in Firestore, injected data can lead to application logic errors or bypass security controls.
    - Information disclosure: While not directly leaking data, modifying data can indirectly lead to information disclosure depending on how the application uses the data.
- **Vulnerability Rank:** High
- **Currently implemented mitigations:**
    - Filename parsing for collection and document key: The function `get_parameters_from_filename` and `regex_search_string` parse the filename to extract the collection ID and document ID key. This provides some level of control over where the data is written, but does not prevent data injection within the document's fields.
    - Document ID constraint validation: The `check_fs_constraints` function validates the document ID against Firestore constraints. This prevents errors due to invalid document IDs but does not sanitize the data being written.
- **Missing mitigations:**
    - Data sanitization and validation: Implement input sanitization and validation for the data extracted from the CSV file before writing to Firestore. This should include:
        - Defining expected data types and formats for each field.
        - Validating data against these expected types and formats.
        - Sanitizing data to prevent injection attacks (e.g., escaping special characters if data is used in further queries or operations).
    - Input validation on filename parameters: While basic parsing exists, more robust validation of the `collection` and `key` parameters extracted from the filename could prevent unexpected behavior.
    - Least privilege principle: Ensure the Cloud Function's service account has the minimum necessary Firestore permissions. While not a direct mitigation for data injection, limiting write access can reduce the potential damage.
- **Preconditions:**
    - An attacker needs to be able to upload a CSV file to the Cloud Storage bucket that triggers the Cloud Function. This typically requires write access to the bucket, or the bucket to be publicly writable (misconfiguration).
    - The Cloud Function must be deployed and configured to process files from the attacker-accessible bucket.
- **Source code analysis:**
    - `python/main.py:csv_to_firestore_trigger`: This function is the entry point triggered by Cloud Storage uploads. It initializes Firestore and Storage clients and calls `csv_to_firestore`.
    - `python/main.py:csv_to_firestore`: This function reads the CSV file using `get_file` and then processes it chunk by chunk using `pd.read_csv`. For each chunk, it iterates through records and calls `set_document`.
    - `python/main.py:set_document`:
        ```python
        def set_document(record, db, batch, timestamp, firestore_path):
          """Constructs and sets firestore documenent in batch based on given record."""
          document_id = firestore_path['document_id']
          record['timestamp'] = timestamp # Adds timestamp to the record
          if firestore_path['document_id'] is not None:
            document_id = str(record[firestore_path['document_id']]) # Document ID is taken from CSV record if specified
            if check_fs_constraints(document_id) is None: # Document ID is validated against constraints
              print(...)
              return False
            if os.getenv('EXCLUDE_DOCUMENT_ID_VALUE') == 'TRUE':
              del record[firestore_path['document_id']] # Optionally remove document ID value from data
          data_path_and_id = db.collection(firestore_path['collection_id']).document(document_id) # Firestore path is constructed
          batch.set(data_path_and_id, record) # Data from record is directly set to Firestore
          return True
        ```
        - **Vulnerability Point:** The `set_document` function directly uses the `record` dictionary, which is derived from the CSV data, to set the Firestore document fields. There is no validation or sanitization of the *values* within the `record` before writing to Firestore. An attacker can control the content of the CSV and thus the content of the Firestore documents.
    - `python/main.py:get_file`: This function retrieves the file from Cloud Storage and decodes it. No vulnerability here directly, but it's the source of the potentially malicious CSV data.

- **Security test case:**
    - Pre-requisites:
        - Deploy the Cloud Function as described in the README.
        - Identify the Cloud Storage bucket that triggers the function (YOUR_TRIGGER_BUCKET_NAME).
        - Have access to upload files to this bucket.
    - Steps:
        1. Create a malicious CSV file named `malicious_data[collection=test_collection].csv` with the following content:
           ```csv
           field1,field2
           malicious_value1,"<script>alert('XSS')</script>"
           ```
           Here, `test_collection` is a Firestore collection you want to write to (or a new one for testing). The `field2` column contains a potential XSS payload (though Firestore itself will likely escape this, the principle of data injection remains valid, and other payloads could be more impactful depending on application usage).
        2. Upload `malicious_data[collection=test_collection.csv` to the Cloud Storage bucket `YOUR_TRIGGER_BUCKET_NAME`.
        3. Wait for the Cloud Function to be triggered and execute (check Cloud Function logs for completion).
        4. Go to the Firestore database in the Google Cloud Console.
        5. Navigate to the `test_collection` collection.
        6. You should see a new document created from the CSV row.
        7. Inspect the document data. You will observe that the `field2` field in Firestore contains the value exactly as provided in the CSV, including the `<script>alert('XSS')</script>` payload (or other malicious data you injected). This demonstrates successful data injection from the CSV into Firestore.
        8. (Optional) To test data overwriting, if you know the document ID (either by specifying a 'key' column or knowing Firestore auto-generated IDs), you can create a CSV that targets an existing document to overwrite its fields.

#### 2. Filename Parameter Injection leading to Collection Override

- **Vulnerability Name:** Filename Parameter Injection leading to Collection Override
- **Description:**
    1. The Cloud Function extracts the Firestore collection ID from the filename using regular expressions.
    2. An attacker can craft a malicious filename that includes a `collection` parameter with a different collection ID than intended by the system owner.
    3. When the Cloud Function processes this file, it will use the attacker-specified collection ID, causing data from the malicious CSV to be written to an unintended Firestore collection.
    4. This can lead to data being written to collections that the attacker should not have access to, potentially overwriting or corrupting existing data in those collections if the document IDs collide, or simply injecting unwanted data.
- **Impact:**
    - **High:** Data written to unintended Firestore collection.
    - Potential data corruption or overwriting in the unintended collection if document IDs collide.
    - Potential injection of malicious or unwanted data into the Firestore database.
    - Possible confusion and operational issues due to data being in the wrong collection.
- **Vulnerability Rank:** High
- **Currently Implemented Mitigations:**
    - None. The code directly extracts the collection ID from the filename without any validation or sanitization of the extracted value.
- **Missing Mitigations:**
    - **Validation and Sanitization of Collection ID:** Implement validation to ensure the extracted collection ID conforms to expected formats and is within an allowed list of collections.
    - **Centralized Configuration:** Store allowed collection IDs in a configuration file or environment variables, instead of relying solely on filename parsing.
    - **Principle of Least Privilege:**  The Cloud Function's service account should ideally have write access only to the intended collection, limiting the impact of a collection override. However, this project does not seem to implement such fine-grained permissions based on filename.
- **Preconditions:**
    - Attacker has the ability to upload files to the Cloud Storage bucket that triggers the Cloud Function.
    - The attacker knows or can guess the naming convention for filenames, specifically the parameter extraction using brackets `[collection=YOUR_COLLECTION_ID]`.
- **Source Code Analysis:**
    1. **`get_parameters_from_filename(filename)` function:**
        ```python
        def get_parameters_from_filename(filename):
          """Receives a filename and returns the defined collection and document id.
          ...
          """
          collection_id = regex_search_string(filename, 'collection') # Extracts collection ID using regex
          document_id = regex_search_string(filename, 'key') # Extracts document ID key using regex
          ...
          return {
                  "collection_id": collection_id,
                  "document_id": document_id
                  }
        ```
        This function calls `regex_search_string` to extract `collection` and `key` parameters from the filename.

    2. **`regex_search_string(filename, parameter)` function:**
        ```python
        def regex_search_string(filename, parameter):
          """Searches parameter in filename.
          ...
          """
          out = re.search(r'\[' + parameter + r'=(.*?)\]', filename) # Regex to find parameters in filename
          if out is None:
            return None
          return out.group().replace('[' + parameter + '=', '').replace(']', '') # Returns extracted value
        ```
        This function uses the regex `r'\[' + parameter + r'=(.*?)\]'` to find parameters within square brackets in the filename. The `(.*?)` part is a capturing group that matches any character (`.`) zero or more times (`*?` non-greedy) between `[`parameter=` and `]`.  **Critically, there is no validation or sanitization of the captured group `(.*?)`**.

    3. **`csv_to_firestore_trigger(event, context)` function:**
        ```python
        def csv_to_firestore_trigger(event, context):
          """Triggered by cloud storage file upload, initializes client file processing.
          ...
          """
          firestore_path = get_parameters_from_filename(event['name']) # Calls function to get parameters from filename
          storage_client, db = storage.Client(), firestore.Client()
          csv_to_firestore(event, storage_client, db, firestore_path) # Passes firestore_path, including attacker-controlled collection_id, to csv_to_firestore
        ```
        The `firestore_path` dictionary, including the `collection_id` extracted from the filename, is directly passed to the `csv_to_firestore` function.

    4. **`csv_to_firestore(event, storage_client, db, firestore_path)` function:**
        ```python
        def csv_to_firestore(event, storage_client, db, firestore_path):
          """Triggered by csv_to_firestore_trigger process and sends file to Firestore.
          ...
          """
          ...
          batch = db.batch() # Initialize Firestore batch
          for record in data_dict:
            if set_document(record, db, batch, chunk_timestamp_utc, firestore_path): # Calls set_document with firestore_path
              row_counter += 1
            else:
              failed_records_counter += 1
          batch.commit()
          ...
        ```
        The `firestore_path` is passed down to `set_document`.

    5. **`set_document(record, db, batch, timestamp, firestore_path)` function:**
        ```python
        def set_document(record, db, batch, timestamp, firestore_path):
          """Constructs and sets firestore documenent in batch based on given record.
          ...
          """
          document_id = firestore_path['document_id']
          ...
          data_path_and_id = db.collection(firestore_path['collection_id']).document(document_id) # Uses collection_id from firestore_path to access Firestore collection
          batch.set(data_path_and_id, record) # Sets the document in the batch for the specified collection
          return True
        ```
        The `set_document` function uses `firestore_path['collection_id']` to determine the Firestore collection to write to. Since this `collection_id` originates from the potentially attacker-controlled filename and is not validated, it allows for collection override.

- **Security Test Case:**
    1. **Precondition:** Deploy the Cloud Function to a Google Cloud Project and set up a Cloud Storage trigger bucket as described in the `README.md`. Assume the intended collection to write data to is named `intended_collection`. Create another collection named `attacker_collection` in the same Firestore database, which is not intended to be used by this Cloud Function under normal circumstances.
    2. **Craft Malicious CSV File:** Create a CSV file (e.g., `malicious_data[collection=attacker_collection].csv`) with the following content:
        ```csv
        field1,field2
        malicious_value1,malicious_value2
        ```
        **Note:** The filename `malicious_data[collection=attacker_collection].csv` contains the `collection` parameter set to `attacker_collection`.
    3. **Upload Malicious CSV File:** Upload the crafted CSV file (`malicious_data[collection=attacker_collection].csv`) to the Cloud Storage trigger bucket.
    4. **Observe Firestore:**
        - Check the Firestore database.
        - Verify that a new document with the data from the malicious CSV file (`malicious_value1`, `malicious_value2`) has been created in the `attacker_collection` collection.
        - Confirm that no data has been written to the intended collection (`intended_collection`) from this upload (unless other files were uploaded to it).
    5. **Expected Result:** The data from the malicious CSV file should be written to the `attacker_collection`, demonstrating that the collection was overridden based on the filename parameter. This confirms the Filename Parameter Injection vulnerability leading to Collection Override.