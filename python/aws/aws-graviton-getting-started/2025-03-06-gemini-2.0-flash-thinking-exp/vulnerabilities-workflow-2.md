## Combined Vulnerability List

This document outlines identified vulnerabilities, detailing their descriptions, impacts, mitigations, and steps to reproduce and test them.

### Outdated Software Vulnerabilities during Migration

- **Vulnerability Name:** Outdated Software Vulnerabilities during Migration
- **Description:** Users following the AWS Graviton Technical Guide for web application migration might inadvertently install or fail to update web server software or language runtimes (e.g., PHP, Node.js), potentially introducing known security vulnerabilities present in older versions. The guide recommends using recent software versions for performance but lacks explicit warnings about security risks associated with outdated software. An attacker could exploit these known vulnerabilities if users deploy applications with outdated and vulnerable software stacks after following the general migration guidance.

    **Steps to trigger vulnerability:**
    1. A user follows the AWS Graviton Technical Guide for web application migration.
    2. The user chooses to install or maintain outdated versions of web server software or language runtimes on their Graviton instances, focusing on functional migration rather than security updates.
    3. The deployed web application runs on outdated and vulnerable software.
    4. An attacker identifies and exploits known security vulnerabilities present in the outdated software version.

- **Impact:** Successful exploitation of vulnerabilities in outdated software can lead to various impacts, including unauthorized access, data breaches, website defacement, and other security compromises within the migrated web application.
- **Vulnerability Rank:** High
- **Currently Implemented Mitigations:**
    - The "Recent software updates relevant to Graviton" section in `README.md` recommends using later versions of software, which indirectly suggests mitigation for both performance and security.
- **Missing Mitigations:**
    - Explicit security warnings and best practices regarding software versions are missing.
    - The guide should prominently highlight the importance of using the latest *secure* versions of web server software and language runtimes.
    - Recommend steps for users to verify and update their software stacks during migration, emphasizing security updates.
- **Preconditions:**
    - A user must follow the AWS Graviton Technical Guide for web application migration.
    - The user must choose to install or maintain outdated versions of web server software or language runtimes on their Graviton instances.
- **Source Code Analysis:**
    - The vulnerability is not in the source code of the project itself but rather in the guidance provided in the documentation, specifically `README.md`.
    - The "Recent software updates relevant to Graviton" section lists software packages and their updated versions for performance improvements.
    - The documentation lacks explicit warnings about security risks associated with outdated software versions and doesn't strongly emphasize security considerations for software versions during migration.
- **Security Test Case:**
    1. Set up a Graviton instance (e.g., using AWS EC2 console) following the "Transitioning to Graviton" guide mentioned in `README.md`.
    2. Install an outdated vulnerable version of PHP (e.g., PHP 5.6, or any version known to have security vulnerabilities) on the Graviton instance. This simulates a user who might not prioritize software updates during migration, focusing solely on the functional migration steps.
    3. Deploy a sample PHP web application with known vulnerabilities exploitable in the installed outdated PHP version. For example, a simple PHP script with a file upload vulnerability known to be present in older PHP versions can be used.
    4. From an attacker's machine (separate from the Graviton instance), use a web browser or a tool like `curl` or `Metasploit` to attempt to exploit the known vulnerability in the deployed PHP application. Target the public IP or DNS of the Graviton instance.
    5. Verify successful exploitation of the vulnerability. For example, in the case of a file upload vulnerability, check if the attacker can successfully upload and execute arbitrary code on the Graviton instance, demonstrating the real-world risk of using outdated software versions and the potential security impact.

### Potential command injection in HPC cluster setup scripts

- **Vulnerability Name:** Potential command injection in HPC cluster setup scripts
- **Description:** The HPC cluster setup instructions in `/code/HPC/README.md` and related scripts use shell commands that could be vulnerable to command injection if the S3 bucket name provided by the user in `hpc7g-ubuntu2004-useast1.yaml` is maliciously crafted. The `hpc7g-ubuntu2004-useast1.yaml` template uses a `CustomActions` script from an S3 bucket provided by the user: `s3://<s3_bucket>/install-gcc-11.sh`. If an attacker can control the content of this S3 bucket or perform a Man-in-The-Middle attack to modify the `hpc7g-ubuntu2004-useast1.yaml` file during cluster creation, they could inject malicious code into the `install-gcc-11.sh` script.

    **Steps to trigger vulnerability:**
    1. An attacker gains control or MitM access to the network traffic when a user creates HPC cluster using `pcluster create-cluster --cluster-name test-cluster --cluster-configuration hpc7g-ubuntu2004-useast1.yaml`.
    2. The attacker modifies the `hpc7g-ubuntu2004-useast1.yaml` file or replaces the `install-gcc-11.sh` script in the targeted S3 bucket with malicious code.
    3. A user creates an HPC cluster using the modified `hpc7g-ubuntu2004-useast1.yaml` or with the compromised S3 bucket.
    4. The malicious script `install-gcc-11.sh` is executed on the head node during cluster creation, leading to command injection.

- **Impact:** Code execution on the head node of the HPC cluster. The attacker can gain control of the head node and potentially the entire cluster.
- **Vulnerability Rank:** Critical
- **Currently Implemented Mitigations:** None in the project files. The documentation does not explicitly warn against using untrusted S3 buckets or modifying the configuration files.
- **Missing Mitigations:**
    - Documentation should strongly warn users against using S3 buckets from untrusted sources for custom action scripts.
    - Implement input validation or sanitization for the S3 bucket name, although this might be complex for S3 URI format.
    - Consider providing example scripts directly within the repository instead of relying on external S3 buckets, or using AWS-signed URLs for the scripts.
- **Preconditions:**
    - User creates an HPC cluster using the provided `hpc7g-ubuntu2004-useast1.yaml` template.
    - Attacker can control the S3 bucket specified in the `CustomActions` or perform a MitM attack to modify the configuration file during cluster creation.
- **Source Code Analysis:**
    - File: `/code/HPC/scripts-setup/hpc7g-ubuntu2004-useast1.yaml`
    - Section: `HeadNode.CustomActions.OnNodeConfigured.Script` and `Scheduling.SlurmQueues.ComputeResources.CustomActions.OnNodeConfigured.Script`
    - Code snippet:
        ```yaml
        CustomActions:
          OnNodeConfigured:
            Script: s3://<s3_bucket>/install-gcc-11.sh
        ```
    - The `Script: s3://<s3_bucket>/install-gcc-11.sh` line in the YAML configuration file indicates that a script from an S3 bucket is fetched and executed on the head node and compute nodes during cluster creation. If the S3 bucket is compromised, this script could be malicious.
- **Security Test Case:**
    1. Create an S3 bucket controlled by the attacker and upload a malicious `install-gcc-11.sh` script to it. This script could simply create a file in `/tmp/pwned`.
    2. Create a modified `hpc7g-ubuntu2004-useast1.yaml` file, replacing `<s3_bucket>` with the attacker-controlled S3 bucket name.
    3. Create an HPC cluster using `pcluster create-cluster --cluster-name test-cluster --cluster-configuration modified-hpc7g-ubuntu2004-useast1.yaml`.
    4. SSH into the head node of the created cluster.
    5. Check if the `/tmp/pwned` file exists. If it exists, it confirms that the malicious script from the attacker-controlled S3 bucket was executed.

### Potential insecure download of Arm Compiler for Linux (ACfL) and Arm Performance Libraries (ArmPL)

- **Vulnerability Name:** Potential insecure download of Arm Compiler for Linux (ACfL) and Arm Performance Libraries (ArmPL)
- **Description:** The scripts `/code/HPC/scripts-setup/0-install-acfl.sh` and `/code/HPC/scripts-setup/1-install-armpl.sh` download Arm Compiler for Linux (ACfL) and Arm Performance Libraries (ArmPL) using `wget` over HTTP. If the download is intercepted via a Man-in-The-Middle attack, a malicious actor could replace the legitimate software packages with compromised versions.

    **Steps to trigger vulnerability:**
    1. A user executes the scripts `/code/HPC/scripts-setup/0-install-acfl.sh` or `/code/HPC/scripts-setup/1-install-armpl.sh`.
    2. An attacker performs a MitM attack and intercepts the HTTP download requests for ACfL or ArmPL.
    3. The attacker substitutes the legitimate tar files with malicious ones.
    4. The scripts proceed to install the malicious software packages.

- **Impact:** Code execution. If a malicious compiler or performance library is installed, any code compiled or linked with these tools could be compromised, leading to arbitrary code execution. This is especially critical for compilers and performance libraries as they are foundational to the security of the entire system.
- **Vulnerability Rank:** Critical
- **Currently Implemented Mitigations:** None. The scripts use plain HTTP for downloading sensitive software packages.
- **Missing Mitigations:**
    - Change download URLs to HTTPS to ensure encrypted and authenticated download channels.
    - Implement integrity checks (e.g., checksum verification) for the downloaded files to detect tampering. Provide checksums in the documentation and scripts.
- **Preconditions:**
    - User executes the scripts `/code/HPC/scripts-setup/0-install-acfl.sh` or `/code/HPC/scripts-setup/1-install-armpl.sh` to install ACfL or ArmPL.
    - Attacker is in a position to perform a MitM attack during the download process.
- **Source Code Analysis:**
    - File: `/code/HPC/scripts-setup/0-install-acfl.sh` and `/code/HPC/scripts-setup/1-install-armpl.sh`
    - Code snippet (example from `0-install-acfl.sh`):
        ```bash
        wget -O arm-compiler-for-linux_23.04.1_Ubuntu-20.04_aarch64.tar 'https://developer.arm.com/-/media/Files/downloads/hpc/arm-compiler-for-linux/23-04-1/arm-compiler-for-linux_23.04.1_Ubuntu-20.04_aarch64.tar?rev=52971e8fa8a8498c834e48776dfd1ca5&revision=52971e8f-a8a8-498c-834e-48776dfd1ca5'
        ```
    - While the provided example uses HTTPS, a review of all download URLs in all scripts is necessary to ensure consistent HTTPS usage. Any HTTP URLs represent a potential vulnerability.
- **Security Test Case:**
    1. Set up a MitM proxy to intercept HTTP traffic.
    2. Run the script `/code/HPC/scripts-setup/0-install-acfl.sh`.
    3. Observe the `wget` command and intercept the download request.
    4. Replace the legitimate `arm-compiler-for-linux_*.tar` file with a malicious file.
    5. Allow the script to proceed with the installation.
    6. Verify if the malicious compiler is installed (e.g., by checking the compiler version or attempting to execute malicious code compiled with it).

### Potential insecure download of Open MPI

- **Vulnerability Name:** Potential insecure download of Open MPI
- **Description:** The scripts `/code/HPC/scripts-setup/2a-install-openmpi-with-acfl.sh` and `/code/HPC/scripts-setup/2b-install-openmpi-with-gcc.sh` download Open MPI using `wget` over HTTP. Similar to the ACfL and ArmPL vulnerability, a MitM attack could replace the legitimate Open MPI package with a compromised version during download.

    **Steps to trigger vulnerability:**
    1. A user executes the scripts `/code/HPC/scripts-setup/2a-install-openmpi-with-acfl.sh` or `/code/HPC/scripts-setup/2b-install-openmpi-with-gcc.sh`.
    2. An attacker performs a MitM attack and intercepts the HTTP download request for Open MPI.
    3. The attacker substitutes the legitimate tar file with a malicious one.
    4. The scripts proceed to install the malicious Open MPI package.

- **Impact:** Code execution. A compromised MPI library can be leveraged to execute malicious code during HPC application execution, potentially affecting all nodes in the cluster if the malicious MPI is distributed.
- **Vulnerability Rank:** Critical
- **Currently Implemented Mitigations:** None. The scripts use plain HTTP for downloading Open MPI.
- **Missing Mitigations:**
    - Change download URLs to HTTPS for encrypted and authenticated download channels.
    - Implement integrity checks (e.g., checksum verification) for the downloaded files. Provide checksums in the documentation and scripts.
- **Preconditions:**
    - User executes the scripts `/code/HPC/scripts-setup/2a-install-openmpi-with-acfl.sh` or `/code/HPC/scripts-setup/2b-install-openmpi-with-gcc.sh` to install Open MPI.
    - Attacker is in a position to perform a MitM attack during the download process.
- **Source Code Analysis:**
    - File: `/code/HPC/scripts-setup/2a-install-openmpi-with-acfl.sh` and `/code/HPC/scripts-setup/2b-install-openmpi-with-gcc.sh`
    - Code snippet (example from `2a-install-openmpi-with-acfl.sh`):
        ```bash
        wget -N https://download.open-mpi.org/release/open-mpi/v4.1/openmpi-4.1.4.tar.gz
        ```
    - The `wget` command uses HTTP for downloading Open MPI.
- **Security Test Case:**
    1. Set up a MitM proxy to intercept HTTP traffic.
    2. Run the script `/code/HPC/scripts-setup/2a-install-openmpi-with-acfl.sh`.
    3. Observe the `wget` command and intercept the download request.
    4. Replace the legitimate `openmpi-*.tar.gz` file with a malicious file.
    5. Allow the script to proceed with the installation.
    6. Verify if the malicious MPI library is installed (e.g., by checking the MPI version or attempting to execute malicious code using MPI).

### Potential insecure download of WRF, WPS and other HPC application tools

- **Vulnerability Name:** Potential insecure download of WRF, WPS and other HPC application tools
- **Description:** Several scripts in `/code/HPC/scripts-wrf/`, `/code/HPC/scripts-openfoam/`, `/code/HPC/scripts-code_saturne/` and `/code/HPC/scripts-gromacs/` download software packages (WRF, WPS, OpenFOAM, Gromacs, Code Saturne, and their dependencies like jasper, zlib, hdf5, netcdf, gromacs benchmark data) using `wget` over HTTP. MitM attacks during these downloads could lead to compromised software installations.

    **Steps to trigger vulnerability:**
    1. A user executes scripts from `/code/HPC/scripts-wrf/`, `/code/HPC/scripts-openfoam/`, `/code/HPC/scripts-code_saturne/` or `/code/HPC/scripts-gromacs/` to install HPC applications.
    2. An attacker performs a MitM attack and intercepts HTTP download requests for WRF, WPS, OpenFOAM, Gromacs, Code Saturne, or their dependencies.
    3. The attacker substitutes the legitimate tar files or other downloaded files with malicious ones.
    4. The scripts proceed to install the compromised software packages and benchmark data.

- **Impact:** Code execution. Compromised HPC applications or libraries can lead to arbitrary code execution during simulations or benchmark runs, potentially affecting the integrity of research and computations.
- **Vulnerability Rank:** High
- **Currently Implemented Mitigations:** None. The scripts use plain HTTP for downloading software packages and data.
- **Missing Mitigations:**
    - Change download URLs to HTTPS where available. For some scientific software, HTTPS might not be consistently available, in which case, prioritize official HTTPS mirrors or repositories.
    - Implement integrity checks (e.g., checksum verification) for all downloaded files. Provide checksums in the documentation and scripts.
- **Preconditions:**
    - User executes scripts to install HPC applications from source.
    - Attacker is in a position to perform a MitM attack during the download process.
- **Source Code Analysis:**
    - Files: Scripts in `/code/HPC/scripts-wrf/`, `/code/HPC/scripts-openfoam/`, and `/code/HPC/scripts-code_saturne/` and `/code/HPC/scripts-gromacs/`
    - Code snippets: Multiple `wget` commands throughout these scripts use HTTP for downloading various software components and data. Examples:
        - `/code/HPC/scripts-wrf/0-install_zlib_1p2.sh`: `wget -N http://zlib.net/zlib-1.2.13.tar.gz`
        - `/code/HPC/scripts-wrf/1-install_hdf5_1p12.sh`: `curl -o hdf5-1.12.0.tar.gz -J -L https://www.hdfgroup.org/package/hdf5-1-12-0-tar-gz/?wpdmdl=14582` (This one uses HTTPS, but many others use HTTP)
        - `/code/HPC/scripts-wrf/3-install_netcdf_c.sh`: `wget -N https://downloads.unidata.ucar.edu/netcdf-c/4.8.1/netcdf-c-4.8.1.tar.gz`
        - `/code/HPC/scripts-wrf/scripts-wps/0-install_jasper.sh`: `wget https://www2.mmm.ucar.edu/wrf/OnLineTutorial/compile_tutorial/tar_files/jasper-1.900.1.tar.gz`
        - `/code/HPC/scripts-openfoam/compile-openfoam-acfl.sh`: `git clone -b OpenFOAM-v2112 https://develop.openfoam.com/Development/openfoam.git` (While git clone is over HTTPS, the initial clone URL should still be verified if possible and submodules should be checked for HTTPS as well).
        - `/code/HPC/scripts-gromacs/compile-gromacs-acfl.sh`: `wget -q http://ftp.gromacs.org/pub/gromacs/gromacs-${gromacs_version}.tar.gz`
        - `/code/HPC/scripts-code_saturne/install-codesaturne-gcc-mpi4.sh`: `wget https://www.code-saturne.org/releases/code_saturne-8.0.2.tar.gz`
- **Security Test Case:**
    1. Set up a MitM proxy to intercept HTTP traffic.
    2. Run any of the HPC application installation scripts (e.g., `/code/HPC/scripts-wrf/install-wrf-tools-acfl.sh`).
    3. Observe the `wget` commands and intercept the download requests for tar files or other resources.
    4. Replace the legitimate files with malicious files.
    5. Allow the script to proceed with the installation.
    6. Run the installed HPC application or benchmark and verify if malicious code execution can be achieved.

### Insecure file permissions in zlib installation script

- **Vulnerability Name:** Insecure file permissions in zlib installation script
- **Description:** The zlib installation guide in `README.md` instructs users to compile and install `zlib-cloudflare` manually. The provided script uses `make install` which, if configured with a prefix in the user's home directory (as shown in the example: `./configure --prefix=$HOME`), may lead to files being installed with insecure permissions (e.g., 777 or world-writable). An attacker could potentially exploit this by replacing the installed zlib library with a malicious one if the user's home directory or the installation path is world-writable or writable by other users on the system.

    **Steps to trigger vulnerability:**
    1. A user follows the zlib installation instructions in `README.md`.
    2. The user executes `git clone https://github.com/cloudflare/zlib.git`.
    3. The user executes `./configure --prefix=$HOME`.
    4. The user executes `make` and `make install`.
    5. If `$HOME/lib` or the effective installation path has insecure permissions, an attacker with write access to these paths can replace the installed zlib library.

- **Impact:** Code execution. If a malicious zlib library is installed, any application linking to it (e.g., OpenJDK as mentioned in the documentation) could be compromised, leading to arbitrary code execution when the application uses zlib functions.
- **Vulnerability Rank:** High
- **Currently Implemented Mitigations:** None in the provided documentation.
- **Missing Mitigations:**
    - Documentation should explicitly warn users about the security implications of installing software in user-writable directories.
    - The installation instructions should recommend using secure file permissions during and after installation (e.g., using `umask` before installation, and verifying permissions after installation).
    - Suggest installing to system-wide directories that are not user-writable, if possible and applicable.
- **Preconditions:**
    - User follows the zlib installation instructions and installs zlib to a user-writable directory.
    - The user-writable directory or installation path has insecure permissions (world-writable or writable by malicious users).
- **Source Code Analysis:**
    - File: `/code/README.md`
    - Section: `zlib on Linux`
    - Code block:
        ```
        git clone https://github.com/cloudflare/zlib.git
        cd zlib
        ./configure --prefix=$HOME
        make
        make install
        ```
    - The `--prefix=$HOME` in `./configure` and `make install` commands can lead to installation in a user-writable directory. `make install` itself doesn't inherently set insecure permissions, but combined with a user-writable `$HOME` and potentially misconfigured `umask`, it increases the risk of insecure permissions.
- **Security Test Case:**
    1. Set up an EC2 instance.
    2. Follow the zlib installation instructions in `/code/README.md`.
    3. After `make install`, check the permissions of the installed zlib library in `$HOME/lib` using `ls -l $HOME/lib/libz.so.1`.
    4. Verify if the permissions are overly permissive (e.g., world-writable).
    5. As a separate user with write access to `$HOME/lib`, attempt to replace the installed zlib library with a malicious one.
    6. Run an application that links to zlib and observe if the malicious library is loaded and if code execution can be achieved.