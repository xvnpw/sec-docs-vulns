## Vulnerabilities Found

### Vulnerability Name: Unauthenticated ADB Access
* Description:
    1. Run the emulator container using `run.sh` or `run-with-gpu.sh`.
    2. Ensure that port 5555 on the host machine is reachable from the attacker's machine. This can happen due to misconfigured firewall rules or running the container on a publicly accessible cloud instance with port 5555 open.
    3. On the attacker's machine, use `adb connect <container-ip>:5555` to establish a connection to the ADB server in the container.
    4. Once connected, the attacker can use `adb shell` to execute arbitrary commands within the Android emulator.
* Impact:
    - An attacker gaining ADB access can fully control the Android emulator, including:
        - Installing and uninstalling applications.
        - Accessing application data and system settings.
        - Monitoring user activity within the emulator.
        - Injecting malware or malicious applications into the emulator.
        - Using the emulator as a pivot point to attack other systems on the network.
* Vulnerability Rank: Critical
* Currently Implemented Mitigations:
    - None. The provided scripts and Dockerfile expose the ADB port without any authentication by default.
* Missing Mitigations:
    - Implement network access control to restrict access to port 5555 to authorized networks or IP addresses.
    - Implement authentication for ADB connections, such as requiring a key or token for access.
    - By default, do not expose port 5555 and only allow access via localhost or a more secure private network.
    - Document the security risks of exposing port 5555 and provide instructions on how to secure ADB access.
* Preconditions:
    - The emulator container is running.
    - Port 5555 on the host machine is reachable by the attacker (e.g., due to public exposure or network misconfiguration).
    - The attacker has ADB installed and configured.
* Source Code Analysis:
    - **/code/run.sh** and **/code/run-with-gpu.sh**: These scripts directly use `docker run` with `--publish 5555:5555/tcp` which exposes port 5555 of the container to the host without any access control.
    ```sh
    docker run \
     --publish 8554:8554/tcp \
     --publish 5555:5555/tcp <docker-image-id>
    ```
    - **/code/emu/templates/Dockerfile**: The Dockerfile EXPOSEs port 5555, making it available for publishing by docker run.
    ```dockerfile
    # This is the ADB port, useful.
    EXPOSE 5555
    ```
    - No authentication mechanisms or network restrictions are implemented in the provided code to protect the exposed ADB port.
* Security Test Case:
    1. Deploy the Android Emulator Container on a publicly accessible cloud instance using `run.sh` script, ensuring port 5555 is exposed to the internet.
    2. On an attacker machine with ADB installed and configured, execute the command: `adb connect <public-ip-of-cloud-instance>:5555`.
    3. If the connection is successful, execute `adb shell getprop ro.product.model`.
    4. If the command returns the model of the Android Emulator, it confirms unauthenticated ADB access.
    5. As a further step, try to install an application using `adb install <path_to_apk>`. If successful, it demonstrates the full impact of arbitrary command execution via ADB.

### Vulnerability Name: Insecure ADB Key Exposure via Web Interface
* Description:
    1. An attacker gains access to the web interface of the emulator.
    2. The attacker uses the provided `development.yaml` docker-compose override or a similar configuration to enable ADB access to the emulator container via port 5555.
    3. Because the `create_web_container.sh` script copies the private ADB key (`~/.android/adbkey`) into the `js/docker/certs` directory and it's included in the built container image when `development.yaml` is used, the attacker can connect to the exposed ADB port (5555) without proper authorization if the port is exposed publicly.
    4. Once connected via ADB, the attacker can execute arbitrary commands on the Android emulator instance as an unprivileged user, potentially leading to further compromise of the emulator environment.
* Impact:
    - Unauthorized access to the Android emulator instance.
    - Remote code execution on the Android emulator.
    - Potential data exfiltration from the emulator.
    - Further exploitation of the environment from within the compromised emulator instance.
* Vulnerability Rank: High
* Currently Implemented Mitigations:
    - The README.md mentions that the web interface is an experimental feature and users should be aware of security implications.
    - Firebase authentication is used to protect gRPC endpoints, but ADB access is not directly protected by this authentication mechanism when `development.yaml` is used.
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

### Vulnerability Name: Insufficient Firebase Authentication Enforcement
* Description:
    1. An attacker identifies that the web interface for the Android Emulator uses Firebase for authentication.
    2. The attacker inspects the Envoy configuration and observes that JWT authentication is enforced for paths starting with `/android.emulation.control` and `/android.emulation.control.Rtc`.
    3. However, the attacker discovers that the Nginx web server, which serves the React application, and the React application itself, do not independently verify Firebase authentication.
    4. The attacker directly accesses the Nginx web server or modifies the client-side React application to remove or bypass any client-side authentication checks.
    5. The attacker then interacts with the emulator through the web interface served by Nginx, potentially sending gRPC requests directly to the emulator's gRPC endpoint (port 8554) without proper Firebase authentication enforced at the application level.
* Impact:
    - Unauthorized Access: Attackers can gain unauthorized access to the Android Emulator instance, potentially controlling the emulator and accessing any data or functionalities exposed through the gRPC interface.
    - Data Breach: If sensitive data is accessible via the emulator or actions performed on the emulator can lead to data exposure, a data breach could occur.
    - Malicious Operations: Attackers could use the compromised emulator instance for malicious activities, such as running unauthorized tests, manipulating emulator state for fraudulent purposes, or using it as a jump point for further attacks.
* Vulnerability Rank: High
* Currently Implemented Mitigations:
    - Firebase Authentication via Envoy Proxy: The project uses Envoy proxy to enforce JWT-based Firebase authentication for gRPC requests targeting `/android.emulation.control` and `/android.emulation.control.Rtc` paths.
* Missing Mitigations:
    - Application-Level Authentication: Missing is a robust authentication mechanism within the Nginx served React application and potentially within the emulator's gRPC service itself to verify Firebase authentication tokens independently of the Envoy proxy.
    - Backend gRPC Endpoint Protection: Ensure that the emulator's gRPC endpoint (port 8554) is not directly accessible from the public internet, and all requests should ideally be routed and authenticated via the Envoy proxy.
* Preconditions:
    - Publicly Accessible Emulator Web Interface: The Android Emulator web interface, including the Nginx server and potentially the gRPC endpoint (port 8554), must be accessible over the internet or an untrusted network.
    - Misconfiguration or Bypass of Envoy Proxy: The attacker needs to bypass or circumvent the Firebase authentication enforced by the Envoy proxy, either by directly accessing Nginx or crafting requests that bypass the proxy’s filtering.
* Source Code Analysis:
    - **`js/docker/envoy.yaml` & `js/develop/envoy.yaml`**: These files configure Envoy proxy to handle authentication. The `jwt_authn` filter is set up, which is a positive security measure, but might be the only line of defense.
    ```yaml
    http_filters:
    - name: envoy.filters.http.cors
      typed_config:
        "@type": type.googleapis.com/envoy.extensions.filters.http.cors.v3.Cors
    - name: envoy.filters.http.jwt_authn
      typed_config:
        "@type": type.googleapis.com/envoy.extensions.filters.http.jwt_authn.v3.JwtAuthentication
        providers:
          firebase_jwt:
            issuer: https://securetoken.google.com/android-emulator-webrtc-demo
            audiences:
            - android-emulator-webrtc-demo
            remote_jwks:
              http_uri:
                uri: https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com
                cluster: jwks_cluster
                timeout: 60s
              cache_duration:
                seconds: 300
        rules:
        - match:
            prefix: "/android.emulation.control"
          requires:
            provider_name: "firebase_jwt"
        - match:
            prefix: "/android.emulation.control.Rtc"
          requires:
            provider_name: "firebase_jwt"
    ```
    - **`js/docker/docker-compose.yaml` & `js/docker/development.yaml`**: These files define the Docker Compose setup and show separation of Nginx and Envoy, potentially allowing direct access to Nginx.
* Security Test Case:
    1. Setup a publicly accessible instance of the Android Emulator web interface using the provided docker-compose files (`js/docker/docker-compose.yaml`).
    2. Identify the public IP address or hostname of the deployed web interface.
    3. Attempt to access the web interface directly through a browser using the public IP address or hostname.
    4. Observe that the React application loads.
    5. Using browser developer tools, examine the network requests made by the React application when interacting with the emulator controls.
    6. Identify the gRPC endpoints being called (likely on port 8554).
    7. Attempt to craft a direct gRPC request to the emulator's gRPC endpoint (port 8554) without including a valid Firebase JWT token in the headers using tools like `grpcurl`.
    8. If successful in sending gRPC requests and receiving responses from the emulator without Firebase authentication, it confirms that the gRPC endpoint is not sufficiently protected beyond the Envoy proxy and that direct access (or bypassed proxy access) is possible.