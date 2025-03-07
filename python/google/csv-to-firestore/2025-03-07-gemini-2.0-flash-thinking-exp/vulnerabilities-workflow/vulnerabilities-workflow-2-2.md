### Vulnerability List

* Vulnerability Name: Filename Parameter Injection leading to Collection Override
* Description:
    1. The Cloud Function extracts the Firestore collection ID from the filename using regular expressions.
    2. An attacker can craft a malicious filename that includes a `collection` parameter with a different collection ID than intended by the system owner.
    3. When the Cloud Function processes this file, it will use the attacker-specified collection ID, causing data from the malicious CSV to be written to an unintended Firestore collection.
    4. This can lead to data being written to collections that the attacker should not have access to, potentially overwriting or corrupting existing data in those collections if the document IDs collide, or simply injecting unwanted data.
* Impact:
    - **High:** Data written to unintended Firestore collection.
    - Potential data corruption or overwriting in the unintended collection if document IDs collide.
    - Potential injection of malicious or unwanted data into the Firestore database.
    - Possible confusion and operational issues due to data being in the wrong collection.
* Vulnerability Rank: High
* Currently Implemented Mitigations:
    - None. The code directly extracts the collection ID from the filename without any validation or sanitization of the extracted value.
* Missing Mitigations:
    - **Validation and Sanitization of Collection ID:** Implement validation to ensure the extracted collection ID conforms to expected formats and is within an allowed list of collections.
    - **Centralized Configuration:** Store allowed collection IDs in a configuration file or environment variables, instead of relying solely on filename parsing.
    - **Principle of Least Privilege:**  The Cloud Function's service account should ideally have write access only to the intended collection, limiting the impact of a collection override. However, this project does not seem to implement such fine-grained permissions based on filename.
* Preconditions:
    - Attacker has the ability to upload files to the Cloud Storage bucket that triggers the Cloud Function.
    - The attacker knows or can guess the naming convention for filenames, specifically the parameter extraction using brackets `[collection=YOUR_COLLECTION_ID]`.
* Source Code Analysis:
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

* Security Test Case:
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