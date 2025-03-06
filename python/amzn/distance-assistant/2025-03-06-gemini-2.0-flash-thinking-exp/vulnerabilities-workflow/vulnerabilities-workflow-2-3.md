### Vulnerability List

* Vulnerability Name: Insecure X Server Access Control via `xhost +local:root`

* Description:
    1. The `Local Execution Instructions` section of the `README.md` file instructs users to run `xhost +local:root` before executing the Docker container.
    2. This command, `xhost +local:root`, disables access control to the X server for local connections made by the root user.
    3. By running this command on the host machine, any process running as root within the Docker container (or even on the host itself if another root process is started) is granted unrestricted access to the X server.
    4. An attacker with local access to the host machine can exploit this permissive X server configuration.
    5. The attacker can then connect to the X server and monitor the graphical output of the DistanceAssistant application running inside the Docker container.
    6. This includes the application's user interface and, critically, the video feed from the Realsense camera, which is intended for social distancing monitoring.
    7. The attacker can effectively "screen-scrape" or record the application's display, gaining unauthorized access to sensitive visual data.

* Impact:
    - **Confidentiality Breach:** Unauthorized access to the video feed from the Realsense camera, compromising the privacy of individuals being monitored for social distancing. The camera feed is intended for local processing and display for social distancing alerts, not for unauthorized remote surveillance.
    - **Information Disclosure:** Potential exposure of other information displayed by the DistanceAssistant application's GUI, which could include configuration details or monitoring statistics.
    - **Abuse of Functionality:** An attacker could potentially inject commands into the X server to interact with the DistanceAssistant application or even other applications running on the X server if other applications are vulnerable to X server attacks. In the context of this application, the primary risk is the unauthorized viewing of the camera feed.

* Vulnerability Rank: High

* Currently Implemented Mitigations:
    - None. The project explicitly instructs users to disable X server access control using `xhost +local:root` in the `README.md` file for local execution.
    - While the kiosk setup uses `xhost +local:root` in `xmonad_autostart.sh`, this is also insecure and doesn't mitigate the vulnerability.

* Missing Mitigations:
    - **Remove the `xhost +local:root` instruction:** The most immediate mitigation is to remove or strongly discourage the use of `xhost +local:root` in the documentation and setup instructions.
    - **Use a more secure X server access control method:** Instead of completely opening up the X server, a more restrictive method should be used to grant access only to the Docker container.  Options include:
        - **`xauth`:** Use `xauth` to securely manage access to the X server. Generate a magic cookie and share it only with the Docker container. This requires more complex setup but significantly improves security.
        - **`docker run --user` and user namespace remapping:** Running the Docker container with a non-root user and utilizing user namespace remapping can reduce the privileges of processes within the container, limiting the impact of vulnerabilities. However, this might require adjustments to file permissions and user configurations within the container.
        - **Restricting access by IP address (less suitable for local connections):** While `xhost` can restrict access by IP address, it's less relevant for local connections and doesn't address the root access issue.
    - **Principle of Least Privilege:** Avoid running the application or parts of it as root inside the container if possible. While ROS often requires root privileges for certain hardware interactions, carefully review and minimize the root processes.
    - **Documentation and Security Best Practices:** Clearly document the security implications of `xhost +local:root` and provide secure alternatives in the `README.md` and any security guidelines.

* Preconditions:
    - Local access to the host machine where the DistanceAssistant Docker container is running. This does not require network access, only physical or console access to the machine.
    - The user must have followed the `Local Execution Instructions` in `README.md` and executed `xhost +local:root`.
    - Docker container must be running and displaying output via the X server.

* Source Code Analysis:
    1. **`README.md`:** The `Local Execution Instructions` section clearly states:
        ```markdown
        # IMPORTANT!!
        # allow connections to X server
        xhost +local:root

        # NOTE: The realsense camera should be connected to the host.
        docker run ...
        ```
        This instruction is provided to resolve "Display Failures" as described in the Troubleshooting section, indicating that the application relies on X server access for its GUI.

    2. **`/code/run.bash`:** This script is the entrypoint for the Docker container. It sets up the ROS environment and launches the `distance_assistant` ROS launch file. It does not directly contain `xhost +local:root`, reinforcing that this command is expected to be run on the host *before* starting the container.
        ```bash
        #!/bin/bash

        # strict mode
        set -eo pipefail
        IFS=$'\n\t'

        # This script is execute when the docker container starts.
        chmod +x /home/catkin_ws/src/DistanceAssistant/scripts/distance_assistant_node.py
        source /home/catkin_ws/devel/setup.sh
        roslaunch distance_assistant distance_assistant.launch
        ```

    3. **`/code/distance_assistant_ansible/ansible/roles/da_kiosk/files/xmonad_autostart.sh`:** This script, used for the kiosk setup, *also* includes `xhost +local:root`. This means the vulnerability is present in both local execution and kiosk modes.
        ```bash
        #!/bin/bash
        ...
        # permit display
        xhost +local:root
        ...
        ```

    **Visualization:**

    ```
    Host Machine                                 Docker Container
    -----------------------                      -----------------------
    1. User executes:                         |
       `xhost +local:root`                    |
       (Disables X server access control)      |
    -----------------------                      -----------------------
    2. User executes:                         | 1. `run.bash` (entrypoint)
       `docker run ...`                         |    - Sets up ROS
                                                |    - Launches `distance_assistant` ROS node
    -----------------------                      -----------------------
    3. Attacker (local user) can now:           | 2. `distance_assistant_node.py`
       - Connect to X server                  |    - Runs DistanceAssistant application
       - Monitor display output of             |    - Displays UI and camera feed on X server
         DistanceAssistant container          |
       - Capture camera feed                  |
    -----------------------                      -----------------------
    ```

* Security Test Case:
    **Assumptions:**
    - Attacker has local user access to the machine where DistanceAssistant is running.
    - DistanceAssistant Docker container is running according to the `Local Execution Instructions` in `README.md`, including the execution of `xhost +local:root`.
    - The host machine has `xterm` installed (or another X client).

    **Steps:**
    1. **Set up DistanceAssistant:** Follow the `Host Setup`, `Build Instructions`, and `Local Execution Instructions` in the `README.md` to build and run the DistanceAssistant Docker container on a test machine. Ensure you execute `xhost +local:root` before running the `docker run` command.
    2. **Gain local access as attacker:** Log in to the test machine as a different local user (or the same user, opening a new terminal). This simulates an attacker with local access.
    3. **Connect to the X server:** Open an `xterm` (or another X client application like `xvncviewer`, `xwd`, etc.) on the attacker's local session. Since `xhost +local:root` was executed, access should be granted without any authentication.
        ```bash
        xterm -display :0
        ```
        (If the DISPLAY environment variable is not set to `:0`, adjust accordingly.  `:0` is the most common default.)
    4. **Verify access to DistanceAssistant display:** Observe the newly opened `xterm` window. It should appear on the same X server display where the DistanceAssistant application is running. This confirms that the attacker's process has successfully connected to the X server.
    5. **Capture the application display (optional, but demonstrates impact more clearly):** Use `xwd` (X Window Dump) to capture the entire X server display or a specific window.
        - To capture the entire display and save it to `display.xwd`:
          ```bash
          xwd -root -display :0 -out display.xwd
          ```
        - To identify the DistanceAssistant application window and capture it specifically (requires `xwininfo`):
          ```bash
          xwininfo -display :0 # Click on the DistanceAssistant window to get its ID
          xwd -id <window_id_from_xwininfo> -display :0 -out da_window.xwd
          ```
        6. **Analyze captured data:** Examine the captured `display.xwd` or `da_window.xwd` file. You should see the graphical output of the DistanceAssistant application, including the camera feed and any UI elements. This confirms that the attacker has successfully gained unauthorized access to the application's visual output due to the insecure `xhost +local:root` command.

This test case demonstrates that an attacker with local access can easily monitor the DistanceAssistant application's display and camera feed by exploiting the insecure X server configuration enabled by `xhost +local:root`.