- Vulnerability Name: Unverified Download of Pre-built Binaries in Mason
- Description: The `mason.py` script downloads and extracts pre-built binaries from the `mason_repository` without any integrity verification. This lack of verification allows for a potential supply chain attack. An attacker who gains control over the `mason_repository` or performs a man-in-the-middle attack can replace legitimate pre-built binaries with malicious ones. When a user builds a project that uses this skeleton and Mason, the build process will download and extract these compromised binaries, leading to arbitrary code execution on the user's machine during the build or runtime if the malicious binaries are used in the final product.

    Steps to trigger the vulnerability:
    1. An attacker compromises the `mason_repository` (e.g., `https://mason-binaries.s3.amazonaws.com`) or sets up a man-in-the-middle attack to intercept requests to this repository.
    2. The attacker replaces a legitimate package archive (e.g., `boost-1.66.0.tar.gz`) with a malicious archive containing backdoored libraries or executables.
    3. A user clones the `python-cpp-skel` project and attempts to build it by running `pip install .` or `pip install -e .`.
    4. The `setup.py` script uses `mason.py` to download the `boost` dependency.
    5. `mason.py` downloads the malicious `boost-1.66.0.tar.gz` archive from the compromised repository or through the man-in-the-middle attack.
    6. `mason.py` extracts the contents of the malicious archive into the `mason_packages` directory without any integrity checks.
    7. The build process then uses the compromised libraries or executables from `mason_packages`, potentially leading to arbitrary code execution during the build or when the installed library is used.

- Impact: Critical. Arbitrary code execution on the developer's machine during the build process and potentially on the end-user's machine if the built library is distributed and used. This can lead to complete system compromise, data theft, and malware installation.
- Vulnerability Rank: Critical
- Currently implemented mitigations: None. The current implementation of `mason.py` does not include any mechanisms for verifying the integrity or authenticity of downloaded packages. It downloads and extracts archives without any checks.
- Missing mitigations:
    - Implement integrity checks for downloaded archives. This can be achieved by:
        - Using checksums (e.g., SHA256) to verify the downloaded archive against a known good checksum. The checksums should be stored securely and retrieved from a trusted source, ideally separate from the binary repository itself.
        - Using digital signatures to verify the authenticity and integrity of the downloaded archives. This involves signing the archives with a private key and verifying the signature using a corresponding public key.
    - Use HTTPS for all downloads from `mason_repository` to prevent man-in-the-middle attacks during the download process. While HTTPS encrypts the communication channel, it does not prevent compromise of the repository itself.
    - Consider using a more robust and secure package management system that is designed with security in mind and provides built-in mechanisms for package verification and secure distribution.
- Preconditions:
    - The attacker must be able to compromise the `mason_repository` or perform a man-in-the-middle attack between the user and the repository.
    - The user must build a project that uses `mason.py` to download dependencies. In this specific project, building the C++ extension triggers the download of `boost` using Mason.
- Source code analysis:
    1. `build_scripts/mason.py`: The `Mason.use` function is responsible for downloading and extracting packages.
    2. The function constructs the download URL using `self.mason_repository` and package details:
       ```python
       url = "{0}/{1}.tar.gz".format(self.mason_repository, slug)
       ```
    3. It then uses `urlretrieve` to download the archive:
       ```python
       urlretrieve(url, cache_path)
       ```
       This download happens over HTTP if `self.mason_repository` is not using HTTPS, and even if it is HTTPS, there is no verification of the server's certificate or hostname in the provided code, relying on system-level TLS implementation. However, more critically, there is no integrity check of the downloaded content itself after downloading.
    4. Finally, it extracts the downloaded archive using `tarfile.open` and `tar.extractall`:
       ```python
       tar = tarfile.open(cache_path)
       tar.extractall(install_path)
       tar.close()
       ```
       The `extractall` function will extract all files from the archive without any validation of the contents. If the archive is malicious, this step will place malicious files onto the user's system.

- Security test case:
    1. **Setup a malicious repository:**
        - Create a simple HTTP server (e.g., using `python -m http.server 8000` in a directory).
        - In this directory, create the directory structure to mimic the `mason_repository`, e.g., `osx-x86_64/boost/1.66.0/`.
        - Create a malicious tar.gz archive `boost-1.66.0.tar.gz` inside this directory. This archive should contain a simple malicious script (e.g., `evil.sh`) and a dummy `mason.ini` file. The `evil.sh` script could simply print "PWNED" to stdout or create a file to indicate successful execution. Example `evil.sh`:
          ```sh
          #!/bin/bash
          echo "PWNED" > /tmp/pwned.txt
          ```
          Make `evil.sh` executable: `chmod +x evil.sh`.
          Create a `mason.ini` (can be dummy for this test):
          ```ini
          [package]
          name=boost
          version=1.66.0
          platform=osx
          platform_version=x86_64
          include_dirs=include
          static_libs=lib/libboost_dummy.a
          ```
          Create the `tar.gz` archive: `tar -czvf boost-1.66.0.tar.gz evil.sh mason.ini`
    2. **Modify `mason.py` to use the malicious repository:**
        - In `build_scripts/mason.py`, temporarily change the `mason_repository` variable in the `Mason` class `__init__` method to point to your malicious HTTP server, e.g., `"http://localhost:8000"`.
    3. **Build the project:**
        - Navigate to the `code` directory of the `python-cpp-skel` project in your terminal.
        - Run `pip install .` or `pip install -e .`. This will trigger the build process and the download of the `boost` package from your malicious repository.
    4. **Verify the exploit:**
        - After the `pip install` command completes, check if the `evil.sh` script has been extracted to `mason_packages/osx-x86_64/boost/1.66.0/evil.sh`.
        - Check if the `/tmp/pwned.txt` file exists, which indicates that the `evil.sh` script was executed during or after the extraction (depending on how you designed your malicious archive and test setup - for this test case execution during extraction is simulated by presence of file after pip install).
        - Alternatively, you can modify `setup.py` to execute the `evil.sh` script explicitly after the Mason download to directly demonstrate code execution. For example, add a post-install script in `setup.py` or manually run `mason_packages/osx-x86_64/boost/1.66.0/evil.sh` after `pip install`.

This test case demonstrates that by controlling the `mason_repository`, an attacker can inject and execute arbitrary code on the machine of a user building the `python-cpp-skel` project.