- vulnerability name: Unauthenticated ADB Access
  - description: |
      The Android Debug Bridge (ADB) port 5555 is exposed by default in the `run.sh` and `run-with-gpu.sh` scripts and Dockerfile without any authentication mechanism. An attacker on the same network or the public internet (if port 5555 is exposed publicly) can connect to the ADB server running within the Docker container without any credentials.

      Steps to trigger vulnerability:
      1. Run the emulator container using `run.sh` or `run-with-gpu.sh`.
      2. Ensure that port 5555 on the host machine is reachable from the attacker's machine. This can happen due to misconfigured firewall rules or running the container on a publicly accessible cloud instance with port 5555 open.
      3. On the attacker's machine, use `adb connect <container-ip>:5555` to establish a connection to the ADB server in the container.
      4. Once connected, the attacker can use `adb shell` to execute arbitrary commands within the Android emulator.
  - impact: |
      An attacker gaining ADB access can fully control the Android emulator, including:
      - Installing and uninstalling applications.
      - Accessing application data and system settings.
      - Monitoring user activity within the emulator.
      - Injecting malware or malicious applications into the emulator.
      - Using the emulator as a pivot point to attack other systems on the network.
  - vulnerability rank: Critical
  - currently implemented mitigations:
      - None. The provided scripts and Dockerfile expose the ADB port without any authentication by default.
  - missing mitigations:
      - Implement network access control to restrict access to port 5555 to authorized networks or IP addresses.
      - Implement authentication for ADB connections, such as requiring a key or token for access.
      - By default, do not expose port 5555 and only allow access via localhost or a more secure private network.
      - Document the security risks of exposing port 5555 and provide instructions on how to secure ADB access.
  - preconditions:
      - The emulator container is running.
      - Port 5555 on the host machine is reachable by the attacker (e.g., due to public exposure or network misconfiguration).
      - The attacker has ADB installed and configured.
  - source code analysis: |
      - **/code/run.sh** and **/code/run-with-gpu.sh**: These scripts directly use `docker run` with `--publish 5555:5555/tcp` which exposes port 5555 of the container to the host without any access control.
      ```sh
      docker run \
       --publish 8554:8554/tcp \
       --publish 5554:5555/tcp <docker-image-id>
      ```
      - **/code/emu/templates/Dockerfile**: The Dockerfile EXPOSEs port 5555, making it available for publishing by docker run.
      ```dockerfile
      # This is the ADB port, useful.
      EXPOSE 5555
      ```
      - No authentication mechanisms or network restrictions are implemented in the provided code to protect the exposed ADB port.
  - security test case: |
      1. Deploy the Android Emulator Container on a publicly accessible cloud instance using `run.sh` script, ensuring port 5555 is exposed to the internet.
      2. On an attacker machine with ADB installed and configured, execute the command: `adb connect <public-ip-of-cloud-instance>:5555`.
      3. If the connection is successful, execute `adb shell getprop ro.product.model`.
      4. If the command returns the model of the Android Emulator, it confirms unauthenticated ADB access.
      5. As a further step, try to install an application using `adb install <path_to_apk>`. If successful, it demonstrates the full impact of arbitrary command execution via ADB.