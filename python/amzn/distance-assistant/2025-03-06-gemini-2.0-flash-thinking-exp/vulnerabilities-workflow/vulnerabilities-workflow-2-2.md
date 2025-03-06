- Vulnerability name: Insecure X11 Server Exposure via xhost +local:root

- Description:
    - The DistanceAssistant project, in both its local execution instructions and kiosk setup, utilizes the `xhost +local:root` command.
    - This command disables access control to the X11 server for local connections from the root user.
    - Step 1: An attacker gains limited access to the Docker container, for example by exploiting an unrelated vulnerability within the application or via misconfiguration.
    - Step 2: From within the Docker container, the attacker leverages the exposed X11 server by setting the `DISPLAY` environment variable to point to the host's X11 server (e.g., `:0`).
    - Step 3: The attacker can now execute graphical applications within the Docker container that will be displayed on the host system's X11 server.
    - Step 4: This allows the attacker to interact with the host system's graphical environment, potentially leading to further compromise of the host, such as keylogging, screen capture, or interaction with other GUI applications running on the host.

- Impact:
    - By gaining access to the host's X11 server, an attacker can escalate privileges and compromise the host system from within the Docker container.
    - This can lead to unauthorized access to sensitive information, modification of system settings, or disruption of services on the host machine.
    - In a kiosk setup, this vulnerability is particularly critical as it can allow a user to break out of the intended kiosk environment and access the underlying operating system.

- Vulnerability rank: High

- Currently implemented mitigations:
    - None. The project explicitly instructs users to use `xhost +local:root` in the README.md for local execution and includes it in the kiosk setup scripts (`xmonad_autostart.sh`).

- Missing mitigations:
    - Removal of the `xhost +local:root` command.
    - Implementation of more secure X11 access control methods, such as using `xauth` and sharing specific authorization cookies with the Docker container instead of completely opening up the X11 server.
    - Documentation should be updated to strongly discourage the use of `xhost +local:root` and recommend secure alternatives.

- Preconditions:
    - The DistanceAssistant Docker container must be running on a host system with an X11 server.
    - The user must have followed the project's instructions to run the Docker container, which includes executing `xhost +local:root` or using the kiosk setup which executes this command automatically.
    - An attacker must gain initial, limited access to the Docker container.

- Source code analysis:
    - File: `/code/README.md`
        - Under "Local Execution Instructions", the README.md explicitly instructs the user to run `xhost +local:root` before executing the Docker container:
        ```bash
        # IMPORTANT!!
        # allow connections to X server
        xhost +local:root
        ```
        - This command is provided without sufficient security warnings or alternative secure methods.
    - File: `/code/distance_assistant_ansible/ansible/roles/da_kiosk/files/xmonad_autostart.sh`
        - In the kiosk setup script `xmonad_autostart.sh`, the `xhost +local:root` command is directly embedded:
        ```bash
        # permit display
        xhost +local:root
        ```
        - This means that in the default kiosk configuration, the X11 server is insecurely exposed by default.
        - Visualization:
            ```
            Host System (X11 Server) <-----> Docker Container (DistanceAssistant)
                       ^
                       | xhost +local:root
                       |
            Insecure X11 Access
            ```

- Security test case:
    - Step 1: Set up a host machine with Ubuntu 18.04 or similar Linux distribution and install Docker, NVIDIA Container Toolkit, and the DistanceAssistant project as described in the README.md.
    - Step 2: Build and run the DistanceAssistant Docker container using the provided `docker run` command, ensuring `xhost +local:root` is executed on the host beforehand.
    - Step 3: Gain access to the running Docker container. This can be simulated by using `docker exec -it <container_id> /bin/bash` or by exploiting a hypothetical vulnerability within the application itself.
    - Step 4: Inside the Docker container, set the `DISPLAY` environment variable to match the host's display, typically `:0`.
        ```bash
        export DISPLAY=:0
        ```
    - Step 5: Attempt to run a graphical application from within the Docker container. For example, install `xterm` inside the container (`apt-get update && apt-get install xterm`) and then run `xterm`.
    - Step 6: Observe that the `xterm` window appears on the host system's display, demonstrating successful access to the host's X11 server from within the container.
    - Step 7: As a further test, attempt to capture a screenshot of the host's display from within the container using `import -window root host_screenshot.png`.
    - Step 8: Verify that `host_screenshot.png` contains a screenshot of the host system's desktop, confirming the attacker's ability to interact with and extract information from the host's graphical environment.
    - Step 9: For kiosk setup, follow the kiosk setup instructions in README.md. After kiosk is set up and running, gain access to a shell (e.g. via SSH if enabled, or by physical access and switching TTY). Repeat steps 4-8 from within the kiosk environment to demonstrate the same vulnerability in the kiosk setup.