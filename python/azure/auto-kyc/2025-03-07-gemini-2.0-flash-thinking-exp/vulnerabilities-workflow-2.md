## Combined Vulnerability List

### 1. Path Traversal in Document Processing

- **Vulnerability Name:** Path Traversal in Document Processing
- **Description:** An attacker can craft a malicious document filename containing path traversal characters (e.g., `../`, `..\\`) which, when processed by the backend, could lead to writing files outside of the intended temporary directory (`temp_imgs`). This could potentially overwrite system files or other sensitive files on the server.
    1. An attacker uploads a document with a crafted filename, such as `../../../evil.pdf`.
    2. The backend, specifically the `analyze_documents` function in `api.py` and `IDDocumentProcessor` in `code/utils/id_document_processor.py`, uses this filename to create a temporary file path.
    3. Due to insufficient sanitization of the filename, the path traversal characters are not removed.
    4. When the backend attempts to save or process the document using libraries like `pdf2image` or `PIL`, the crafted path is used.
    5. This results in the backend writing or processing files in an unintended directory, potentially outside of the `temp_imgs` directory.
- **Impact:**
    - **High**: Arbitrary File Write - An attacker could potentially overwrite critical system files, configuration files, or other application files, leading to denial of service, code execution, or data corruption.
- **Vulnerability Rank:** High
- **Currently Implemented Mitigations:**
    - None. The code uses user-provided filenames directly when creating temporary file paths without any sanitization or validation.
- **Missing Mitigations:**
    - **Filename Sanitization**: Implement robust filename sanitization to remove or replace path traversal characters and enforce allowed characters.
    - **Path Normalization**: Use secure path handling functions to normalize paths and prevent traversal outside of the intended directory (e.g., using `os.path.basename` to extract only the filename and avoid path components).
    - **Restrict Temporary Directory Permissions**: Configure permissions for the `temp_imgs` directory to limit the potential damage if a path traversal is successful.
- **Preconditions:**
    - The application must be running and accessible to the attacker.
    - The attacker needs to be able to upload documents through the `/api/analyze` endpoint.
- **Source Code Analysis:**
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

- **Security Test Case:**
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

### 2. Remote Code Execution via PDF Processing Vulnerability

- **Vulnerability Name:** Remote Code Execution via PDF Processing Vulnerability
- **Description:** An attacker can upload a maliciously crafted PDF document to the KYC application. The backend, upon receiving the document, saves it to a temporary location and processes it using the `pdf2image` library to convert the PDF into images. If the uploaded PDF is specially crafted to exploit vulnerabilities within `pdf2image` or its underlying image processing libraries (like Pillow/PIL), it can lead to arbitrary code execution on the server. This occurs because `pdf2image` and PIL, while powerful libraries, have historically been susceptible to vulnerabilities when handling complex or malformed image files, including those embedded within PDFs. Successful exploitation allows the attacker to gain complete control over the server.
    1. An attacker crafts a malicious PDF document designed to exploit vulnerabilities in document processing libraries.
    2. The attacker accesses the KYC application's web interface, specifically the document upload functionality.
    3. The attacker uploads the malicious PDF file through the `/api/analyze` endpoint.
    4. The backend server receives the PDF file and processes it using `pdf2image` library to convert it into images.
    5. If the `pdf2image` library or its dependencies (like Ghostscript or Poppler) are vulnerable to processing the crafted PDF, it can lead to arbitrary code execution on the server.
- **Impact:**
    - **Critical.** Remote Code Execution (RCE) vulnerabilities are considered critical as they allow an attacker to execute arbitrary code on the server.
    - This can lead to:
        - **Full Server Compromise:** The attacker can gain complete control over the application server.
        - **Data Breach:** Sensitive customer data stored in the Cosmos DB or Blob Storage could be accessed, modified, or deleted.
        - **Service Disruption:** The application's availability and functionality can be severely impacted, leading to denial of service or data corruption.
        - **Lateral Movement:** The compromised server can be used as a pivot point to attack other internal systems and resources.
- **Vulnerability Rank:** Critical
- **Currently Implemented Mitigations:**
    - None. The code does not implement any specific security measures to sanitize or validate uploaded documents before processing them with potentially vulnerable libraries.
- **Missing Mitigations:**
    - **Input Validation:** Implement strict validation on the type and format of uploaded files. While the application expects document uploads, it does not seem to verify if the uploaded file is a benign PDF or image file before processing. Implement strict checks on uploaded file types and enforce size limits. Verify that the uploaded file is actually a PDF and not disguised as one.
    - **Content Sanitization:** Sanitize or preprocess uploaded documents to remove potentially malicious embedded code or objects before processing them with document processing libraries.
    - **Sandboxing:** Isolate the document processing environment in a sandbox to limit the impact of a successful exploit. Use containerization or virtualization to restrict access from the document processing service to the host system and network.
    - **Secure Document Processing Libraries:** Consider using more secure alternatives to `pdf2image` or ensure that `pdf2image` and its dependencies are kept up-to-date with the latest security patches. Regularly update all dependencies, especially those involved in processing external inputs.
    - **Principle of Least Privilege:** Run the document processing service with minimal necessary privileges to reduce the potential damage from a successful exploit.
    - **Library Updates and Security Scanning:** Regularly update `pdf2image`, Pillow/PIL, and other dependencies to their latest versions to patch known vulnerabilities. Implement automated security scanning tools to identify vulnerable dependencies.
    - **Consider Alternative Libraries:** Evaluate and potentially switch to more secure document processing libraries or services that are less prone to vulnerabilities or offer better security features.
    - **File Size Limits:** Implement limits on the size of uploaded files to mitigate potential buffer overflow vulnerabilities and resource exhaustion.
- **Preconditions:**
    - The application must be running and accessible over the network.
    - The attacker must be able to access the `/api/analyze` endpoint, which is intended for document upload and analysis.
    - The KYC application must be publicly accessible and running.
    - An attacker must be able to access the document upload functionality of the application, which is likely available to any user intending to use the KYC service.
    - The backend server must be running the FastAPI application with `pdf2image` and Pillow/PIL libraries installed for document processing.
- **Source Code Analysis:**
    1. `api.py` defines the `/api/analyze` endpoint as a POST request handler.
    2. The `analyze_documents` function in `api.py` is called when a request is made to `/api/analyze`.
    3. Inside `analyze_documents`, the `id_document` which is a base64 encoded string of the uploaded file, and `id_document_name` are extracted from the request.
    4. `base64.b64decode(info.get("id_document", ""))` decodes the base64 encoded document content.
    5. `write_bytes_to_file(id_document, im_fn, "wb")` saves the decoded bytes to a file in the `temp_imgs` directory. The filename `im_fn` is derived from `id_document_name` which is directly taken from user input.
    6. `IDDocumentProcessor(customer_id=customer_id, doc_path=im_fn)` is initialized, passing the path to the saved document.
    7. Inside `IDDocumentProcessor.__init__` in `/code/code/utils/id_document_processor.py`:
        ```python
        if doc_path.endswith(".pdf"):
            pdf_images = convert_from_path(doc_path)
            self.images = []

            for pdf_image in pdf_images:
                fn = os.path.join(self.work_dir, str(uuid.uuid4()))
                pdf_image.save(fn)
                self.images.append(fn)
        ```
        - If the uploaded document's name ends with `.pdf`, the code uses `pdf2image.convert_from_path(doc_path)`. This function from the `pdf2image` library is used to convert PDF documents to PIL Image objects.
        - `pdf2image` relies on external tools like `Poppler` (via `pdftoppm`) or Ghostscript to perform the conversion. Vulnerabilities in these underlying tools or in `pdf2image` itself can be exploited by malicious PDFs.
        - The converted images are saved as PNG files using `pdf_image.save(fn)` from PIL (implicitly). PIL itself can also have vulnerabilities when processing image files, although the primary risk here is from `pdf2image` and its dependencies.
        - The application proceeds to analyze the generated images, but the initial step of PDF conversion using `pdf2image` is where the Remote Code Execution vulnerability lies.
        - No validation or sanitization of the PDF document is performed before it's processed by `pdf2image`.

    - **Visualization:**
        ```mermaid
        graph LR
            A[Client Uploads Malicious PDF] --> B(/api/analyze Endpoint in api.py);
            B --> C[base64 Decode and Save to Temp File];
            C --> D[IDDocumentProcessor Instantiation];
            D --> E[extract_document Method in id_document_processor.py];
            E --> F[pdf2image.convert_from_path(doc_path)];
            F --> G[Vulnerability in pdf2image/PIL Exploited];
            G --> H[Remote Code Execution on Server];
        ```

- **Security Test Case:**
    1. Set up a testing environment with the KYC application running.
    2. Prepare a malicious PDF file. This PDF should be crafted to exploit a known vulnerability in `pdf2image`, Poppler, or Ghostscript. Publicly available resources like exploit databases can be used to find or adapt existing exploits. For example, you could search for "pdf2image RCE exploit" or "Poppler vulnerability".
    3. Use a tool like `curl` or a web browser's developer tools to send a POST request to the `/api/analyze` endpoint.
    4. The request should include:
        - A valid `customer_id` in the request body (`info` dictionary).
        - The malicious PDF file content, base64 encoded, as the value for the `id_document` field in the request body (`info` dictionary).
        - A filename ending in `.pdf` for the `id_document_name` field in the request body (`info` dictionary).
    5. Example `curl` command (replace with actual malicious PDF base64 and customer ID):
       ```bash
       curl -X POST -H "Content-Type: application/json" -d '{"customer_id": "test_customer_id", "id_document_name": "malicious.pdf", "id_document": "<BASE64_ENCODED_MALICIOUS_PDF_CONTENT>"}' http://localhost:80/api/analyze
       ```
    6. Monitor the server logs and system behavior after sending the request. Look for signs of code execution, such as:
        - Unexpected errors or crashes in the application.
        - Creation of unexpected files in the `temp_imgs` directory or other parts of the file system.
        - Outbound network connections initiated from the server to attacker-controlled IPs.
        - Changes in system user accounts or privileges.
        - If a specific exploit is used that attempts to create a reverse shell, try to connect to the reverse shell listener set up before sending the request.
    7. If any of these signs are observed, it confirms the Remote Code Execution vulnerability. A successful test would demonstrate the ability to execute arbitrary commands on the server by uploading a malicious PDF document.
    8. **Preparation:**
        - Set up a testing environment that mirrors the production environment as closely as possible, including the same versions of Python, FastAPI, `pdf2image`, and Pillow/PIL.
        - Obtain or create a malicious PDF file specifically designed to exploit known vulnerabilities in `pdf2image` or Pillow/PIL. Public resources like exploit databases or security research papers can be consulted for creating or obtaining such files. For testing purposes, start with publicly available exploit samples, or use tools to craft them.
        - Ensure you have access to monitor the backend server (e.g., via logs, network traffic monitoring tools, or a debugging session if possible in your test environment).

    9. **Access the Application:**
        - Access the publicly available instance of the KYC application through a web browser.

    10. **Navigate to Document Upload:**
        - Locate the document upload functionality in the application's frontend. This is typically found in the user interface for initiating the KYC process, likely in a section where users are prompted to upload their ID documents.

    11. **Upload Malicious PDF:**
        - Using the document upload form, select and upload the prepared malicious PDF file. Submit the file as if it were a legitimate ID document.

    12. **Trigger Analysis:**
        - After uploading, initiate the document analysis process. This might involve clicking an "Analyze" button or submitting the form containing the uploaded document. This action will trigger the backend to process the uploaded PDF.

    13. **Monitor Server for Exploitation:**
        - **Network Monitoring:** Monitor network traffic from the server for any unusual outbound connections to external, attacker-controlled servers. This could indicate a reverse shell or data exfiltration attempt.
        - **System Logs:** Check the application server's logs (FastAPI logs, system logs) for error messages, unusual activity, or signs of unexpected process execution.
        - **File System Monitoring:** Observe the server's file system for any unexpected file creation, modification, or deletion in temporary directories or other sensitive areas.
        - **Process Monitoring:** Monitor running processes on the server for any new, unauthorized processes spawned after uploading the malicious PDF.
        - **Response Delay/Errors:** Note if the application becomes unresponsive or returns errors after uploading the malicious PDF, which could indicate a crash or exploit attempt.

    14. **Verify Code Execution (If Possible):**
        - **Out-of-band confirmation:** If the malicious PDF is designed to trigger an out-of-band callback (e.g., DNS lookup, HTTP request to a controlled server), monitor for these callbacks. Successful callbacks confirm code execution.
        - **File creation:** Design the exploit to create a specific file in a known location on the server (e.g., `/tmp/pwned.txt`). Check for the existence of this file after uploading and analysis.
        - **Command execution (in a safe test environment):** In a controlled, non-production test environment, you might attempt to execute commands like `whoami` or `hostname` and check the output to confirm code execution. **Never attempt this on a production system.**

    15. **Confirmation of Vulnerability:**
        - If any of the monitoring steps reveal signs of remote code execution (e.g., successful callbacks, unexpected file creation, server compromise), then the Remote Code Execution vulnerability via malicious PDF upload is confirmed.

    16. **Remediation and Reporting:**
        - Once confirmed, document the vulnerability with detailed steps to reproduce and the observed impact.
        - Prioritize remediation by implementing the missing mitigations described above, focusing on input validation, secure processing environments, and library updates.
        - Follow responsible disclosure practices and report the vulnerability to the project maintainers or security team.