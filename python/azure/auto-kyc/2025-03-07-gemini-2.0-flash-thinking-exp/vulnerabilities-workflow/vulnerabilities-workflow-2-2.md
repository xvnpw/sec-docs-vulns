- Vulnerability Name: Remote Code Execution via PDF Processing Vulnerability
- Description:
    1. An attacker crafts a malicious PDF document designed to exploit vulnerabilities in document processing libraries.
    2. The attacker accesses the KYC application's web interface, specifically the document upload functionality.
    3. The attacker uploads the malicious PDF file through the `/api/analyze` endpoint.
    4. The backend server receives the PDF file and processes it using `pdf2image` library to convert it into images.
    5. If the `pdf2image` library or its dependencies (like Ghostscript) are vulnerable to processing the crafted PDF, it can lead to arbitrary code execution on the server.
- Impact:
    - Complete compromise of the backend server.
    - Unauthorized access to sensitive customer data stored in the database and blob storage.
    - Potential for lateral movement to other systems within the network.
    - Data breach and reputational damage.
    - System downtime and disruption of KYC service.
- Vulnerability Rank: Critical
- Currently Implemented Mitigations:
    - None. The code does not implement any specific security measures to sanitize or validate uploaded documents before processing them with potentially vulnerable libraries.
- Missing Mitigations:
    - Input validation: Implement strict checks on uploaded file types and enforce size limits. Verify that the uploaded file is actually a PDF and not disguised as one.
    - Content sanitization: Sanitize or preprocess uploaded documents to remove potentially malicious embedded code or objects before processing them with document processing libraries.
    - Sandboxing: Isolate the document processing environment in a sandbox to limit the impact of a successful exploit. Use containerization or virtualization to restrict access from the document processing service to the host system and network.
    - Secure document processing libraries: Consider using more secure alternatives to `pdf2image` or ensure that `pdf2image` and its dependencies are kept up-to-date with the latest security patches. Regularly update all dependencies, especially those involved in processing external inputs.
    - Principle of least privilege: Run the document processing service with minimal necessary privileges to reduce the potential damage from a successful exploit.
- Preconditions:
    - The application must be running and accessible over the network.
    - The attacker must be able to access the `/api/analyze` endpoint, which is intended for document upload and analysis.
- Source Code Analysis:
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
    8. The converted images are saved as PNG files using `pdf_image.save(fn)` from PIL (implicitly). PIL itself can also have vulnerabilities when processing image files, although the primary risk here is from `pdf2image` and its dependencies.
    9. The application proceeds to analyze the generated images, but the initial step of PDF conversion using `pdf2image` is where the Remote Code Execution vulnerability lies.
    10. No validation or sanitization of the PDF document is performed before it's processed by `pdf2image`.

- Security Test Case:
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