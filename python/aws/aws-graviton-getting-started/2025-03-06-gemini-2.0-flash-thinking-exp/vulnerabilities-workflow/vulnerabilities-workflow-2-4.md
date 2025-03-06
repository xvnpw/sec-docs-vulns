- Vulnerability Name: Potential command injection in HPC cluster setup scripts
    - Description:
        - The HPC cluster setup instructions in `/code/HPC/README.md` and related scripts use shell commands that could be vulnerable to command injection if the S3 bucket name provided by the user in `hpc7g-ubuntu2004-useast1.yaml` is maliciously crafted.
        - The `hpc7g-ubuntu2004-useast1.yaml` template uses a `CustomActions` script from an S3 bucket provided by the user: `s3://<s3_bucket>/install-gcc-11.sh`. If an attacker can control the content of this S3 bucket or perform a Man-in-The-Middle attack to modify the `hpc7g-ubuntu2004-useast1.yaml` file during cluster creation, they could inject malicious code into the `install-gcc-11.sh` script.
        - Step-by-step trigger:
            1. Attacker gains control or MitM access to the network traffic when a user creates HPC cluster using `pcluster create-cluster --cluster-name test-cluster --cluster-configuration hpc7g-ubuntu2004-useast1.yaml`.
            2. Attacker modifies the `hpc7g-ubuntu2004-useast1.yaml` file or replaces the `install-gcc-11.sh` script in the targeted S3 bucket with malicious code.
            3. User creates HPC cluster using the modified `hpc7g-ubuntu2004-useast1.yaml` or with the compromised S3 bucket.
            4. The malicious script `install-gcc-11.sh` is executed on the head node during cluster creation, leading to command injection.
    - Impact:
        - Code execution on the head node of the HPC cluster. The attacker can gain control of the head node and potentially the entire cluster.
    - Vulnerability rank: critical
    - Currently implemented mitigations:
        - None in the project files. The documentation does not explicitly warn against using untrusted S3 buckets or modifying the configuration files.
    - Missing mitigations:
        - Documentation should strongly warn users against using S3 buckets from untrusted sources for custom action scripts.
        - Implement input validation or sanitization for the S3 bucket name, although this might be complex for S3 URI format.
        - Consider providing example scripts directly within the repository instead of relying on external S3 buckets, or using AWS-signed URLs for the scripts.
    - Preconditions:
        - User creates an HPC cluster using the provided `hpc7g-ubuntu2004-useast1.yaml` template.
        - Attacker can control the S3 bucket specified in the `CustomActions` or perform a MitM attack to modify the configuration file during cluster creation.
    - Source code analysis:
        - File: `/code/HPC/scripts-setup/hpc7g-ubuntu2004-useast1.yaml`
        - Section: `HeadNode.CustomActions.OnNodeConfigured.Script` and `Scheduling.SlurmQueues.ComputeResources.CustomActions.OnNodeConfigured.Script`
        - Code snippet:
        ```yaml
        CustomActions:
          OnNodeConfigured:
            Script: s3://<s3_bucket>/install-gcc-11.sh
        ```
        - The `Script: s3://<s3_bucket>/install-gcc-11.sh` line in the YAML configuration file indicates that a script from an S3 bucket is fetched and executed on the head node and compute nodes during cluster creation. If the S3 bucket is compromised, this script could be malicious.
    - Security test case:
        1. Create an S3 bucket controlled by the attacker and upload a malicious `install-gcc-11.sh` script to it. This script could simply create a file in `/tmp/pwned`.
        2. Create a modified `hpc7g-ubuntu2004-useast1.yaml` file, replacing `<s3_bucket>` with the attacker-controlled S3 bucket name.
        3. Create an HPC cluster using `pcluster create-cluster --cluster-name test-cluster --cluster-configuration modified-hpc7g-ubuntu2004-useast1.yaml`.
        4. SSH into the head node of the created cluster.
        5. Check if the `/tmp/pwned` file exists. If it exists, it confirms that the malicious script from the attacker-controlled S3 bucket was executed.

- Vulnerability Name: Potential insecure download of Arm Compiler for Linux (ACfL) and Arm Performance Libraries (ArmPL)
    - Description:
        - The scripts `/code/HPC/scripts-setup/0-install-acfl.sh` and `/code/HPC/scripts-setup/1-install-armpl.sh` download Arm Compiler for Linux (ACfL) and Arm Performance Libraries (ArmPL) using `wget` over HTTP.
        - If the download is intercepted via a Man-in-The-Middle attack, a malicious actor could replace the legitimate software packages with compromised versions.
        - Step-by-step trigger:
            1. User executes the scripts `/code/HPC/scripts-setup/0-install-acfl.sh` or `/code/HPC/scripts-setup/1-install-armpl.sh`.
            2. Attacker performs a MitM attack and intercepts the HTTP download requests for ACfL or ArmPL.
            3. Attacker substitutes the legitimate tar files with malicious ones.
            4. The scripts proceed to install the malicious software packages.
    - Impact:
        - Code execution. If a malicious compiler or performance library is installed, any code compiled or linked with these tools could be compromised, leading to arbitrary code execution. This is especially critical for compilers and performance libraries as they are foundational to the security of the entire system.
    - Vulnerability rank: critical
    - Currently implemented mitigations:
        - None. The scripts use plain HTTP for downloading sensitive software packages.
    - Missing mitigations:
        - Change download URLs to HTTPS to ensure encrypted and authenticated download channels.
        - Implement integrity checks (e.g., checksum verification) for the downloaded files to detect tampering. Provide checksums in the documentation and scripts.
    - Preconditions:
        - User executes the scripts `/code/HPC/scripts-setup/0-install-acfl.sh` or `/code/HPC/scripts-setup/1-install-armpl.sh` to install ACfL or ArmPL.
        - Attacker is in a position to perform a MitM attack during the download process.
    - Source code analysis:
        - File: `/code/HPC/scripts-setup/0-install-acfl.sh` and `/code/HPC/scripts-setup/1-install-armpl.sh`
        - Code snippet (example from `0-install-acfl.sh`):
        ```bash
        wget -O arm-compiler-for-linux_23.04.1_Ubuntu-20.04_aarch64.tar 'https://developer.arm.com/-/media/Files/downloads/hpc/arm-compiler-for-linux/23-04-1/arm-compiler-for-linux_23.04.1_Ubuntu-20.04_aarch64.tar?rev=52971e8fa8a8498c834e48776dfd1ca5&revision=52971e8f-a8a8-498c-834e-48776dfd1ca5'
        ```
        - The `wget` command uses HTTPS in the provided example. However, it's important to verify all download URLs in all scripts and documentation and ensure they consistently use HTTPS. If there are any HTTP URLs, they represent a potential vulnerability.
    - Security test case:
        1. Set up a MitM proxy to intercept HTTP traffic.
        2. Run the script `/code/HPC/scripts-setup/0-install-acfl.sh`.
        3. Observe the `wget` command and intercept the download request.
        4. Replace the legitimate `arm-compiler-for-linux_*.tar` file with a malicious file.
        5. Allow the script to proceed with the installation.
        6. Verify if the malicious compiler is installed (e.g., by checking the compiler version or attempting to execute malicious code compiled with it).

- Vulnerability Name: Potential insecure download of Open MPI
    - Description:
        - The scripts `/code/HPC/scripts-setup/2a-install-openmpi-with-acfl.sh` and `/code/HPC/scripts-setup/2b-install-openmpi-with-gcc.sh` download Open MPI using `wget` over HTTP.
        - Similar to the ACfL and ArmPL vulnerability, a MitM attack could replace the legitimate Open MPI package with a compromised version during download.
        - Step-by-step trigger:
            1. User executes the scripts `/code/HPC/scripts-setup/2a-install-openmpi-with-acfl.sh` or `/code/HPC/scripts-setup/2b-install-openmpi-with-gcc.sh`.
            2. Attacker performs a MitM attack and intercepts the HTTP download request for Open MPI.
            3. Attacker substitutes the legitimate tar file with a malicious one.
            4. The scripts proceed to install the malicious Open MPI package.
    - Impact:
        - Code execution. A compromised MPI library can be leveraged to execute malicious code during HPC application execution, potentially affecting all nodes in the cluster if the malicious MPI is distributed.
    - Vulnerability rank: critical
    - Currently implemented mitigations:
        - None. The scripts use plain HTTP for downloading Open MPI.
    - Missing mitigations:
        - Change download URLs to HTTPS for encrypted and authenticated download channels.
        - Implement integrity checks (e.g., checksum verification) for the downloaded files. Provide checksums in the documentation and scripts.
    - Preconditions:
        - User executes the scripts `/code/HPC/scripts-setup/2a-install-openmpi-with-acfl.sh` or `/code/HPC/scripts-setup/2b-install-openmpi-with-gcc.sh` to install Open MPI.
        - Attacker is in a position to perform a MitM attack during the download process.
    - Source code analysis:
        - File: `/code/HPC/scripts-setup/2a-install-openmpi-with-acfl.sh` and `/code/HPC/scripts-setup/2b-install-openmpi-with-gcc.sh`
        - Code snippet (example from `2a-install-openmpi-with-acfl.sh`):
        ```bash
        wget -N https://download.open-mpi.org/release/open-mpi/v4.1/openmpi-4.1.4.tar.gz
        ```
        - The `wget` command uses HTTP for downloading Open MPI.
    - Security test case:
        1. Set up a MitM proxy to intercept HTTP traffic.
        2. Run the script `/code/HPC/scripts-setup/2a-install-openmpi-with-acfl.sh`.
        3. Observe the `wget` command and intercept the download request.
        4. Replace the legitimate `openmpi-*.tar.gz` file with a malicious file.
        5. Allow the script to proceed with the installation.
        6. Verify if the malicious MPI library is installed (e.g., by checking the MPI version or attempting to execute malicious code using MPI).

- Vulnerability Name: Potential insecure download of WRF, WPS and other HPC application tools
    - Description:
        - Several scripts in `/code/HPC/scripts-wrf/` and `/code/HPC/scripts-openfoam/` download software packages (WRF, WPS, OpenFOAM, Gromacs, Code Saturne, and their dependencies like jasper, zlib, hdf5, netcdf, gromacs benchmark data) using `wget` over HTTP.
        - MitM attacks during these downloads could lead to compromised software installations.
        - Step-by-step trigger:
            1. User executes scripts from `/code/HPC/scripts-wrf/` or `/code/HPC/scripts-openfoam/` to install HPC applications.
            2. Attacker performs a MitM attack and intercepts HTTP download requests for WRF, WPS, OpenFOAM, Gromacs, Code Saturne, or their dependencies.
            3. Attacker substitutes the legitimate tar files or other downloaded files with malicious ones.
            4. The scripts proceed to install the compromised software packages and benchmark data.
    - Impact:
        - Code execution. Compromised HPC applications or libraries can lead to arbitrary code execution during simulations or benchmark runs, potentially affecting the integrity of research and computations.
    - Vulnerability rank: high
    - Currently implemented mitigations:
        - None. The scripts use plain HTTP for downloading software packages and data.
    - Missing mitigations:
        - Change download URLs to HTTPS where available. For some scientific software, HTTPS might not be consistently available, in which case, prioritize official HTTPS mirrors or repositories.
        - Implement integrity checks (e.g., checksum verification) for all downloaded files. Provide checksums in the documentation and scripts.
    - Preconditions:
        - User executes scripts to install HPC applications from source.
        - Attacker is in a position to perform a MitM attack during the download process.
    - Source code analysis:
        - Files: Scripts in `/code/HPC/scripts-wrf/`, `/code/HPC/scripts-openfoam/`, and `/code/HPC/scripts-code_saturne/` and `/code/HPC/scripts-gromacs/`
        - Code snippets: Multiple `wget` commands throughout these scripts use HTTP for downloading various software components and data. Examples:
            - `/code/HPC/scripts-wrf/0-install_zlib_1p2.sh`: `wget -N http://zlib.net/zlib-1.2.13.tar.gz`
            - `/code/HPC/scripts-wrf/1-install_hdf5_1p12.sh`: `curl -o hdf5-1.12.0.tar.gz -J -L https://www.hdfgroup.org/package/hdf5-1-12-0-tar-gz/?wpdmdl=14582` (This one uses HTTPS, but many others use HTTP)
            - `/code/HPC/scripts-wrf/3-install_netcdf_c.sh`: `wget -N https://downloads.unidata.ucar.edu/netcdf-c/4.8.1/netcdf-c-4.8.1.tar.gz`
            - `/code/HPC/scripts-wrf/scripts-wps/0-install_jasper.sh`: `wget https://www2.mmm.ucar.edu/wrf/OnLineTutorial/compile_tutorial/tar_files/jasper-1.900.1.tar.gz`
            - `/code/HPC/scripts-openfoam/compile-openfoam-acfl.sh`: `git clone -b OpenFOAM-v2112 https://develop.openfoam.com/Development/openfoam.git` (While git clone is over HTTPS, the initial clone URL should still be verified if possible and submodules should be checked for HTTPS as well).
            - `/code/HPC/scripts-gromacs/compile-gromacs-acfl.sh`: `wget -q http://ftp.gromacs.org/pub/gromacs/gromacs-${gromacs_version}.tar.gz`
            - `/code/HPC/scripts-code_saturne/install-codesaturne-gcc-mpi4.sh`: `wget https://www.code-saturne.org/releases/code_saturne-8.0.2.tar.gz`
    - Security test case:
        1. Set up a MitM proxy to intercept HTTP traffic.
        2. Run any of the HPC application installation scripts (e.g., `/code/HPC/scripts-wrf/install-wrf-tools-acfl.sh`).
        3. Observe the `wget` commands and intercept the download requests for tar files or other resources.
        4. Replace the legitimate files with malicious files.
        5. Allow the script to proceed with the installation.
        6. Run the installed HPC application or benchmark and verify if malicious code execution can be achieved.

- Vulnerability Name: Insecure file permissions in zlib installation script
    - Description:
        - The zlib installation guide in `README.md` instructs users to compile and install `zlib-cloudflare` manually.
        - The provided script uses `make install` which, if configured with a prefix in the user's home directory (as shown in the example: `./configure --prefix=$HOME`), may lead to files being installed with insecure permissions (e.g., 777 or world-writable).
        - An attacker could potentially exploit this by replacing the installed zlib library with a malicious one if the user's home directory or the installation path is world-writable or writable by other users on the system.
        - Step-by-step trigger:
            1. User follows the zlib installation instructions in `README.md`.
            2. User executes `git clone https://github.com/cloudflare/zlib.git`.
            3. User executes `./configure --prefix=$HOME`.
            4. User executes `make` and `make install`.
            5. If `$HOME/lib` or the effective installation path has insecure permissions, an attacker with write access to these paths can replace the installed zlib library.
    - Impact:
        - Code execution. If a malicious zlib library is installed, any application linking to it (e.g., OpenJDK as mentioned in the documentation) could be compromised, leading to arbitrary code execution when the application uses zlib functions.
    - Vulnerability rank: high
    - Currently implemented mitigations:
        - None in the provided documentation.
    - Missing mitigations:
        - Documentation should explicitly warn users about the security implications of installing software in user-writable directories.
        - The installation instructions should recommend using secure file permissions during and after installation (e.g., using `umask` before installation, and verifying permissions after installation).
        - Suggest installing to system-wide directories that are not user-writable, if possible and applicable.
    - Preconditions:
        - User follows the zlib installation instructions and installs zlib to a user-writable directory.
        - The user-writable directory or installation path has insecure permissions (world-writable or writable by malicious users).
    - Source code analysis:
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
    - Security test case:
        1. Set up an EC2 instance.
        2. Follow the zlib installation instructions in `/code/README.md`.
        3. After `make install`, check the permissions of the installed zlib library in `$HOME/lib` using `ls -l $HOME/lib/libz.so.1`.
        4. Verify if the permissions are overly permissive (e.g., world-writable).
        5. As a separate user with write access to `$HOME/lib`, attempt to replace the installed zlib library with a malicious one.
        6. Run an application that links to zlib and observe if the malicious library is loaded and if code execution can be achieved.