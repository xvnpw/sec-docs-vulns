- Vulnerability Name: **Path Traversal in Document Processing**
- Description: An attacker can craft a malicious document filename containing path traversal characters (e.g., `../`, `..\\`) which, when processed by the backend, could lead to writing files outside of the intended temporary directory (`temp_imgs`). This could potentially overwrite system files or other sensitive files on the server.
    1. An attacker uploads a document with a crafted filename, such as `../../../evil.pdf`.
    2. The backend, specifically the `analyze_documents` function in `api.py` and `IDDocumentProcessor` in `code/utils/id_document_processor.py`, uses this filename to create a temporary file path.
    3. Due to insufficient sanitization of the filename, the path traversal characters are not removed.
    4. When the backend attempts to save or process the document using libraries like `pdf2image` or `PIL`, the crafted path is used.
    5. This results in the backend writing or processing files in an unintended directory, potentially outside of the `temp_imgs` directory.
- Impact:
    - **High**: Arbitrary File Write - An attacker could potentially overwrite critical system files, configuration files, or other application files, leading to denial of service, code execution, or data corruption.
- Vulnerability Rank: **High**
- Currently Implemented Mitigations:
    - None. The code uses user-provided filenames directly when creating temporary file paths without any sanitization or validation.
- Missing Mitigations:
    - **Filename Sanitization**: Implement robust filename sanitization to remove or replace path traversal characters and enforce allowed characters.
    - **Path Normalization**: Use secure path handling functions to normalize paths and prevent traversal outside of the intended directory (e.g., using `os.path.basename` to extract only the filename and avoid path components).
    - **Restrict Temporary Directory Permissions**: Configure permissions for the `temp_imgs` directory to limit the potential damage if a path traversal is successful.
- Preconditions:
    - The application must be running and accessible to the attacker.
    - The attacker needs to be able to upload documents through the `/api/analyze` endpoint.
- Source Code Analysis:
    1. **File: `/code/api.py` - `analyze_documents` function:**
        ```python
        @app.post("/api/analyze")
        async def analyze_documents(info: dict):
            ...
            id_document_name = info.get("id_document_name", "")
            ...
            work_dir = "temp_imgs"
            os.makedirs(work_dir, exist_ok=True)
            im_fn = os.path.join(work_dir, id_document_name) # Vulnerable line - filename from request is directly used in path join
            write_bytes_to_file(id_document, im_fn, "wb")
            doc_processor = IDDocumentProcessor(customer_id=customer_id, doc_path=im_fn)
            return doc_processor.compare_document_to_database()
        ```
        - The `analyze_documents` function retrieves the `id_document_name` directly from the request (`info` dictionary, which comes from user input).
        - It then uses `os.path.join(work_dir, id_document_name)` to construct the temporary file path `im_fn`.
        - If `id_document_name` contains path traversal characters like `../../../`, `os.path.join` will resolve the path relative to `work_dir`, but it will still allow going outside of the intended `work_dir` base.

    2. **File: `/code/utils/general_helpers.py` - `write_bytes_to_file` function:**
        ```python
        def write_bytes_to_file(byte_data, filename, mode='wb'):
            try:
                filename = filename.replace("\\", "/") # Path manipulation - replace backslashes but not sanitize path components
                with open(filename, mode) as file: # File is opened and written to at the potentially attacker-controlled path
                    file.write(byte_data)
                ...
            except Exception as e:
                ...
        ```
        - The `write_bytes_to_file` function, called by `analyze_documents`, receives the potentially malicious `filename`.
        - While it replaces backslashes with forward slashes, it does not sanitize path traversal sequences like `../` or `..\\`.
        - The `open(filename, mode)` function will then create and write to the file at the path specified by the attacker-controlled `filename`.

    **Visualization:**

    ```
    User Upload (filename: "../../../evil.pdf") --> /api/analyze --> analyze_documents
    analyze_documents --> os.path.join("temp_imgs", "../../../evil.pdf") --> "temp_imgs/../../../evil.pdf" (resolves to "../../evil.pdf" relative to the application root)
    analyze_documents --> write_bytes_to_file(..., "../../evil.pdf")
    write_bytes_to_file --> open("../../evil.pdf", 'wb') --> File written outside temp_imgs
    ```

- Security Test Case:
    1. **Prepare a malicious document:** Create a dummy PDF or image file.
    2. **Craft a malicious filename:** Rename the dummy document to `../../../evil.pdf`.
    3. **Access the application:** Open a web browser and navigate to the KYC application's frontend (e.g., `http://localhost:3000`).
    4. **Upload the document:**
        - Go to the "Upload Documents" page.
        - Upload the renamed file (`../../../evil.pdf`).
        - Navigate to the "Document Comparison" page.
        - Select the uploaded document `../../../evil.pdf` in the Document Viewer.
        - Click "Analyze Documents".
    5. **Observe the backend server:** Check the server's filesystem (e.g., by examining logs or directly if possible) to see if a file named `evil.pdf` has been created in a directory outside of the `temp_imgs` directory, potentially closer to the root of the application or even system directories, depending on the application's working directory and permissions.
    6. **Expected Result:** If the vulnerability exists, you should find the `evil.pdf` file written outside the `temp_imgs` directory, demonstrating successful path traversal. For example, if the application is run from `/app/code`, the file might be written to `/app/evil.pdf` or even `/evil.pdf` if permissions allow.