- vulnerability name: Insecure ISO Remastering via Malicious Source ISO
- description: An attacker can compromise the integrity of the GiftStick bootable image by providing a maliciously crafted Xubuntu ISO as the `--source_iso` argument to the `remaster.sh` script. The `remaster.sh` script directly uses the provided ISO to create the bootable image without performing any integrity checks. If an attacker can trick the user into using a modified ISO, the attacker can inject arbitrary code into the generated GiftStick image. When a target machine boots from this compromised GiftStick, the attacker's malicious code will be executed.
- impact: Critical. Arbitrary code execution on the target machine when booting from the maliciously crafted GiftStick. This allows the attacker to completely compromise the target system, potentially stealing sensitive data, installing persistent backdoors, or causing irreparable damage.
- vulnerability rank: Critical
- currently implemented mitigations: None. The script directly uses the provided ISO without any validation.
- missing mitigations:
    - Implement integrity checks for the source ISO. This could involve verifying a checksum (like SHA256) of the ISO against a known good value.
    - Digital signature verification of the ISO would provide stronger assurance of authenticity and integrity.
- preconditions:
    - The attacker needs to convince a user to use a malicious ISO file as the source for creating the GiftStick image. This relies on social engineering.
    - The user must have the Google Cloud SDK installed and configured, as required by `remaster.sh`.
- source code analysis:
    - File: `/code/tools/remaster.sh`
    - The `remaster.sh` script takes the `--source_iso` argument, which is stored in the `FLAGS_SOURCE_ISO` variable after argument parsing in the `parse_arguments` function.
    - ```bash
      function assert_sourceiso_flag {
        if [[ "${FLAGS_SKIP_ISO_REMASTER}" == "false" ]]; then
          if [[ ! "${FLAGS_SOURCE_ISO}" ]]; then
            die "Please specify a source ISO to remaster with --source_iso"
          fi
          if [[ ! -f "${FLAGS_SOURCE_ISO}" ]]; then
            die "${FLAGS_SOURCE_ISO} is not found"
          fi
          if [[ "${FLAGS_SOURCE_ISO}" != *xubuntu* ]]; then
            echo "WARNING: This auto-remastering tool will probably not behave properly on a non xubuntu image"
            echo "press enter to continue anyway."
            read -r
          fi
          SOURCE_ISO=$(readlink -m "${FLAGS_SOURCE_ISO}")
        else
          if [[ ! "${FLAGS_REMASTERED_ISO}" ]]; then
            die "Please specify a remastered ISO with --remastered_iso"
          fi
        fi
      }
      ```
    - The `assert_sourceiso_flag` function checks if `--source_iso` is provided and if the file exists. It also issues a warning if the ISO filename does not contain "xubuntu". However, it does not perform any cryptographic integrity checks.
    - The `SOURCE_ISO` variable, which is derived from `FLAGS_SOURCE_ISO`, is then used in the `unpack_iso` function:
    - ```bash
      function unpack_iso {
        local -r iso_file=$1
        local -r iso_unpack_dir=$2
        local -r iso_mountpoint="${REMASTER_WORKDIR_PATH}/remaster-iso-mount"

        msg "unpacking iso ${iso_file} to ${iso_unpack_dir}"
        mkdir "${iso_mountpoint}"
        sudo mount -o ro,loop "${iso_file}" "${iso_mountpoint}"
        sudo cp -a "${iso_mountpoint}" "${iso_unpack_dir}"
        sudo umount "${iso_mountpoint}"
      }
      ```
    - The `unpack_iso` function directly mounts and copies the provided ISO content. If a malicious ISO is provided, its content will be copied into the GiftStick image without any security checks.
- security test case:
    - Step 1: Create a malicious Xubuntu ISO. This can be done by downloading a legitimate Xubuntu 20.04 ISO, modifying it to include a reverse shell or other malicious payload (e.g., by altering files within the ISO filesystem), and then rebuilding the ISO image.
    - Step 2: Prepare a testing environment with Google Cloud SDK configured as required by `remaster.sh`.
    - Step 3: Run `remaster.sh` using the malicious ISO created in Step 1 as the `--source_iso` argument. For example:
      ```bash
      bash tools/remaster.sh \
        --project your-gcp-project \
        --bucket giftstick-test-bucket \
        --source_iso malicious-xubuntu-20.04.iso
      ```
      Replace `your-gcp-project` and `giftstick-test-bucket` with your GCP project and bucket names. `malicious-xubuntu-20.04.iso` is the path to the malicious ISO.
    - Step 4: Write the generated GiftStick image to a USB drive.
    - Step 5: Boot a test machine from the USB drive created in Step 4.
    - Step 6: Observe if the malicious payload from the modified ISO is executed on the test machine, confirming arbitrary code execution. For instance, check for a reverse shell connection back to the attacker's machine or any other injected malicious behavior.

- vulnerability name: Path Traversal in `--extra_gcs_path` leading to potential data overwrite
- description: The `remaster.sh` script uses the `--extra_gcs_path` argument to construct the Google Cloud Storage (GCS) path where forensic evidence will be uploaded. This path is concatenated with a fixed base path (`gs://${FLAGS_GCS_BUCKET_NAME}/forensic_evidence/`) and the automatically generated directory structure based on timestamp and system identifier. If a user provides a crafted `--extra_gcs_path` containing path traversal characters like `../`, they might be able to manipulate the final GCS upload path to write data outside of the intended directory, potentially overwriting existing forensic data or other files in the bucket.
- impact: Medium. Potential for overwriting existing data in the GCS bucket. While objectCreator role prevents overwriting existing objects directly, path traversal might allow overwriting data if the attacker can predict or enumerate existing directory structures.
- vulnerability rank: Medium
- currently implemented mitigations: None. The script directly concatenates the user-provided path without sanitization.
- missing mitigations:
    - Sanitize the `--extra_gcs_path` input to prevent path traversal. This can be achieved by validating the input against a whitelist of allowed characters or by using a function to canonicalize the path and ensure it stays within the intended directory.
- preconditions:
    - The attacker needs to convince a user to use a malicious `extra_gcs_path` argument when running `remaster.sh`. This relies on social engineering.
    - The user must have the Google Cloud SDK installed and configured, as required by `remaster.sh`.
- source code analysis:
    - File: `/code/tools/remaster.sh`
    - The `parse_arguments` function parses the `--extra_gcs_path` argument and stores it in the `FLAGS_EXTRA_GCS_PATH` variable.
    - ```bash
      --extra_gcs_path)
        assert_option_argument "$2" "--extra_gcs_path"
        FLAGS_EXTRA_GCS_PATH="$2"
        shift
        ;;
      --extra_gcs_path=?*)
        FLAGS_EXTRA_GCS_PATH=${1#*=}
        ;;
      --extra_gcs_path=)
        die '--extra_gcs_path requires a non-empty option argument.'
        ;;
      ```
    - The `FLAGS_EXTRA_GCS_PATH` is directly used to construct `GCS_REMOTE_URL` in the `assert_image_flag` function:
    - ```bash
      function assert_image_flag {
        if [[ ! "${FLAGS_IMAGE_FILENAME}" ]]; then
          FLAGS_IMAGE_FILENAME=$DEFAULT_IMAGE_FILENAME
        fi
      }
      ```
      and later in `make_bootable_usb_image`:
      ```bash
      readonly GCS_REMOTE_URL="gs://${FLAGS_GCS_BUCKET_NAME}/forensic_evidence/${FLAGS_EXTRA_GCS_PATH}"
      ...
      cat <<EOFORENSICSH | sudo tee -a "${CONFIG_FILENAME}" > /dev/null
      AUTO_FORENSIC_SCRIPT_NAME="${AUTO_FORENSIC_SCRIPT_NAME}"
      GCS_SA_KEY_FILE="/home/${GIFT_USERNAME}/${GCS_SA_KEY_NAME}"
      GCS_REMOTE_URL="${GCS_REMOTE_URL}"
      EOFORENSICSH
      ```
    - The `GCS_REMOTE_URL` is then embedded into the `config.sh` file within the GiftStick image.
    - During runtime on the target machine, `call_auto_forensicate.sh` sources `config.sh` and uses `GCS_REMOTE_URL` as the upload destination.
    - There is no sanitization of `FLAGS_EXTRA_GCS_PATH`, allowing path traversal characters to be included in the final GCS path.
- security test case:
    - Step 1: Prepare a testing environment with Google Cloud SDK configured as required by `remaster.sh`.
    - Step 2: Run `remaster.sh` with a path traversal payload in `--extra_gcs_path`. For example:
      ```bash
      bash tools/remaster.sh \
        --project your-gcp-project \
        --bucket giftstick-test-bucket \
        --source_iso xubuntu-20.04-desktop-amd64.iso \
        --extra_gcs_path "../../../../../"<< malicious_folder_name >>
      ```
      Replace `your-gcp-project` and `giftstick-test-bucket` with your GCP project and bucket names and  `malicious_folder_name` with a folder name you want to create at a higher level in the bucket.
    - Step 3: Write the generated GiftStick image to a USB drive.
    - Step 4: Boot a test machine from the USB drive created in Step 3 and let the acquisition script run.
    - Step 5: Check the GCS bucket and verify if the evidence data was uploaded to the path constructed with the path traversal payload, e.g., `gs://giftstick-test-bucket/malicious_folder_name/` instead of the default `gs://giftstick-test-bucket/forensic_evidence/<extra_gcs_path>/...`.

- vulnerability name: Potential Command Injection via Malicious `EXTRA_OPTIONS` in `config.sh`
- description: The `remaster.sh` script allows setting extra options for the `auto_forensicate.py` script through the `EXTRA_OPTIONS` variable in the generated `config.sh` file. While the provided code in `remaster.sh` only sets `--disk sdb` for testing purposes, an attacker who gains control over the image creation process (e.g., through the "Insecure ISO Remastering" vulnerability) could inject arbitrary command-line options into `EXTRA_OPTIONS` within `config.sh`. When `call_auto_forensicate.sh` executes `auto_forensicate.py`, these injected options will be passed directly to the Python script. If `auto_forensicate.py` or any of its modules improperly handles these options, it could lead to command injection vulnerabilities, allowing the attacker to execute arbitrary code on the target system.
- impact: High. Arbitrary code execution on the target machine if `auto_forensicate.py` or its modules are vulnerable to command injection through command-line options.
- vulnerability rank: High
- currently implemented mitigations: None. The `EXTRA_OPTIONS` variable is directly passed to the `auto_forensicate.py` script without sanitization.
- missing mitigations:
    - Sanitize or strictly validate the `EXTRA_OPTIONS` in `call_auto_forensicate.sh` before passing them to `auto_forensicate.py`. Ideally, avoid using `EXTRA_OPTIONS` for dynamic configurations that could be attacker-controlled. If dynamic options are necessary, use a safer mechanism like a separate configuration file with a defined schema and validation.
    - Review `auto_forensicate.py` and all modules that process command-line arguments to ensure they are not vulnerable to command injection, especially when handling options derived from external configuration files.
- preconditions:
    - The attacker needs to be able to modify the content of the GiftStick image, for instance, by exploiting the "Insecure ISO Remastering" vulnerability.
    - The attacker needs to inject malicious commands into the `EXTRA_OPTIONS` variable within the `config.sh` file during the image remastering process.
- source code analysis:
    - File: `/code/tools/remaster.sh`
    - The `remaster.sh` script defines `EXTRA_OPTIONS` in `config.sh` based on the `--e2e_test` flag:
      ```bash
      if $FLAGS_BUILD_TEST ; then
        cat <<EOFORENSICSHEXTRA | sudo tee -a "${CONFIG_FILENAME}" > /dev/null
          EXTRA_OPTIONS="--disk sdb"
      EOFORENSICSHEXTRA
      fi
      ```
    - An attacker could modify `post-install-user.sh` or directly alter the remastered ISO to inject malicious commands into `EXTRA_OPTIONS`.
    - File: `/code/tools/remaster_scripts/call_auto_forensicate.sh`
    - The `call_auto_forensicate.sh` script sources `config.sh`, making `EXTRA_OPTIONS` available as a shell variable.
    - ```bash
    source config.sh
    ...
    sudo "${AUTO_FORENSIC_SCRIPT_NAME}" \
      --gs_keyfile="${GCS_SA_KEY_FILE}" \
      --logging stdout \
      --logging stackdriver \
      --log_progress \
      --acquire all \
      ${EXTRA_OPTIONS} "${GCS_REMOTE_URL}/"
    ```
    - The `${EXTRA_OPTIONS}` variable is directly placed within the command line arguments of `auto_forensicate.py`. If `EXTRA_OPTIONS` contains shell-injected commands, they could be executed when `sudo "${AUTO_FORENSIC_SCRIPT_NAME}"` is run.
- security test case:
    - Step 1: Create a modified GiftStick image. Modify the `/code/tools/remaster_scripts/post-install-user.sh` file to inject a malicious payload into the `EXTRA_OPTIONS` variable within the `config.sh` file. For example, append the following to `post-install-user.sh`:
      ```bash
      cat <<EOFORENSICSHEXTRA | sudo tee -a "${CONFIG_FILENAME}" > /dev/null
        EXTRA_OPTIONS="\`touch /tmp/pwned\`"
      EOFORENSICSHEXTRA
      ```
      This payload attempts to create a file `/tmp/pwned` when `auto_forensicate.py` is executed.
    - Step 2: Run `remaster.sh` to generate the modified GiftStick image:
      ```bash
      bash tools/remaster.sh \
        --project your-gcp-project \
        --bucket giftstick-test-bucket \
        --source_iso xubuntu-20.04-desktop-amd64.iso
      ```
    - Step 3: Write the generated GiftStick image to a USB drive.
    - Step 4: Boot a test machine from the USB drive created in Step 3.
    - Step 5: After the system boots and the acquisition script is supposed to run, check if the file `/tmp/pwned` exists on the target system. If the file exists, it confirms that the command injection through `EXTRA_OPTIONS` was successful and arbitrary commands could be executed. For a more impactful test, inject a reverse shell command instead of `touch /tmp/pwned`.