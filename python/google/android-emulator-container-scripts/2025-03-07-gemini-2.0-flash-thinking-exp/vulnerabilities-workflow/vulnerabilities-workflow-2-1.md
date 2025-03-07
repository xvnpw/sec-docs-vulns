* Vulnerability Name: Insecure ADB Key Exposure via Web Interface
* Description:
    1. An attacker gains access to the web interface of the emulator, potentially by exploiting other vulnerabilities or through leaked credentials if authentication is enabled but weak or bypassed.
    2. The attacker uses the provided development.yaml docker-compose override or a similar configuration to enable ADB access to the emulator container via port 5555.
    3. Because the `create_web_container.sh` script copies the private ADB key (`~/.android/adbkey`) into the `js/docker/certs` directory and it's included in the built container image when development.yaml is used, the attacker can connect to the exposed ADB port (5555) without proper authorization if the port is exposed publicly.
    4. Once connected via ADB, the attacker can execute arbitrary commands on the Android emulator instance as an unprivileged user, potentially leading to further compromise of the emulator environment.
* Impact:
    - Unauthorized access to the Android emulator instance.
    - Remote code execution on the Android emulator.
    - Potential data exfiltration from the emulator.
    - Further exploitation of the environment from within the compromised emulator instance.
* Vulnerability Rank: High
* Currently Implemented Mitigations:
    - The README.md mentions that the web interface is an experimental feature and users should be aware of security implications.
    - Firebase authentication is used to protect gRPC endpoints, but ADB access is not directly protected by this authentication mechanism when development.yaml is used.
* Missing Mitigations:
    - Remove the copying of the private adbkey into the docker image, especially for production and public deployments.
    - Implement proper authentication and authorization mechanisms for ADB access when exposed through the web interface.
    - Clearly document the security risks of enabling ADB access in publicly accessible web emulator instances and advise against it.
    - Harden the docker configurations to prevent unintentional exposure of sensitive keys.
* Preconditions:
    - The web interface of the emulator is accessible to the attacker.
    - ADB access is enabled using `development.yaml` or similar configurations and port 5555 is exposed.
    - The attacker has network connectivity to the exposed port 5555.
* Source Code Analysis:
    1. `code/create_web_container.sh`: This script is responsible for creating the web container setup. It includes the following steps:
        - `cp ~/.android/adbkey js/docker/certs`: Copies the private ADB key to the `js/docker/certs` directory.
    2. `code/js/docker/development.yaml`: This docker-compose override file:
        - `secrets: - adbkey`: Defines a docker secret named `adbkey`.
        - `secrets: adbkey: file: ~/.android/adbkey`: Mounts the host's `~/.android/adbkey` as a secret file within the `emulator` service.
        - `ports: - "5555:5555" - "5554:5554"`: Exposes ports 5555 and 5554 of the emulator container to the host.
    3. `code/emu/templates/launch-emulator.sh`: This script within the container:
        - `if [ -s "/run/secrets/adbkey" ]; then`: Checks if the `adbkey` secret is available.
        - `run cp /run/secrets/adbkey /root/.android`: Copies the ADB key from the secret to `/root/.android` if the secret exists.
    4. Visualization:
        ```
        Attacker --> Web Interface (port 80/443) --> Envoy Proxy --> Emulator Container (port 8554 - gRPC, port 5555 - ADB)
                                                            ^
                                                            |
                                         Private ADB Key (~/.android/adbkey) copied to container image (development.yaml)
        ```
    5. The combination of these configurations results in the private ADB key being included in the container image when using `development.yaml` and ADB port 5555 being exposed, allowing unauthorized ADB access.
* Security Test Case:
    1. Deploy the web container using `create_web_container.sh` with `development.yaml` enabled (e.g., `./create_web_container.sh -a -s`).
    2. Ensure port 5555 on the host machine is publicly accessible or accessible from the attacker's network.
    3. On the attacker's machine, use `adb connect <target-ip>:5555` to attempt to connect to the exposed ADB port.
    4. If the connection is successful, execute `adb shell getprop ro.product.model` to verify command execution on the emulator.
    5. Expected Result: The command executes successfully, returning the emulator's product model, proving unauthorized ADB access.