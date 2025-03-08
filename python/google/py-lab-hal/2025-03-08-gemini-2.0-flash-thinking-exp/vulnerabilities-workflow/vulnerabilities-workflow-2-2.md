## Vulnerability List for Py-Lab-HAL Project

### 1. Vulnerability Name: Unauthenticated Network Socket Access to Lab Equipment

- Description:
  1. An application using Py-Lab-HAL is configured to control lab equipment via a network socket.
  2. The application establishes a socket connection to the lab equipment without implementing any authentication or authorization mechanisms.
  3. An attacker on the same network as the lab equipment and the control application can establish a direct socket connection to the lab equipment.
  4. The attacker can then send arbitrary commands through this socket connection to control the lab equipment without needing any valid credentials or permissions.
  5. The lab equipment executes the commands received over the unauthenticated socket connection.

- Impact:
  - Unauthorized control of lab equipment.
  - Potential for malicious actions such as:
    - Modifying equipment settings (e.g., voltage, current, frequency).
    - Disrupting experiments or tests.
    - Damaging equipment by sending harmful commands.
    - Manipulating measurement data.
    - In extreme cases, causing safety hazards depending on the lab equipment controlled.

- Vulnerability Rank: Critical

- Currently Implemented Mitigations:
  - None. The project does not implement any authentication or authorization for socket connections.

- Missing Mitigations:
  - Implement authentication mechanisms for socket connections. Options include:
    - **Password-based authentication:** Require clients to authenticate with a username and password before allowing control.
    - **Token-based authentication:** Use tokens for authentication, which can be more secure than passwords.
    - **Mutual TLS (mTLS):** Implement mTLS to authenticate both the client and the server, and encrypt communication.
  - Implement authorization mechanisms to control what actions authenticated users are allowed to perform.
  - Restrict network access to the socket interface using firewalls or network segmentation to limit the attack surface.
  - Provide clear documentation and warnings to users about the security risks of using socket connections without authentication and recommend secure configuration practices.

- Preconditions:
  - Py-Lab-HAL library is used in an application to control lab equipment.
  - The application is configured to use a socket connection to communicate with the lab equipment.
  - No authentication or authorization is implemented for the socket communication.
  - The attacker is on the same network as the lab equipment and the control application.
  - The lab equipment's socket interface is accessible on the network.

- Source Code Analysis:
  1. **`File: /code/builder.py`**:
     - The `PyLabHALBuilder` class is responsible for building instrument objects.
     - It uses `cominterface.ConnectConfig` to configure the communication interface.
     - For socket connections, it utilizes `cominterface.NetworkConfig` to specify host and port:

     ```python
     build.connection_config = cominterface.ConnectConfig(
         network=cominterface.NetworkConfig(
             host='192.168.11.11',
             port=5025,
         ),
     )
     ```

  2. **`File: /code/cominterface/cominterface.py`**:
     - The `select` function determines the communication interface based on `ConnectConfig`.
     - For network configurations, it instantiates the `Socket` class:
     ```python
     if connect_config.network:
         return socket.Socket(connect_config)
     ```

  3. **`File: /code/cominterface/socket.py`**:
     - The `Socket` class handles socket communication.
     - The `_open` method establishes a socket connection:
     ```python
     self._socket.connect((
         self.connect_config.network.host,
         self.connect_config.network.port,
     ))
     ```
     - The `_send`, `_recv`, and `_query` methods use the established socket to send and receive data:
     ```python
     def _send(self, data: bytes) -> None:
         self._socket.send(data)
     ```
     - **Vulnerability Point:** The `Socket` class and the connection configuration process in `builder.py` and `cominterface.py` **do not include any code for authentication or authorization**. The socket connection is established directly without any security checks.

- Security Test Case:
  1. **Setup**:
     - Configure a lab equipment (e.g., a DC Power Supply if controllable via socket based on documentation, or use a simple network service emulator listening on a port).
     - Create a Py-Lab-HAL application that controls this lab equipment using a socket connection, configured as described in the `README.md` example.
     - Ensure no authentication is configured in the Py-Lab-HAL application.
     - Deploy the Py-Lab-HAL application and the lab equipment on a network accessible to the attacker.
  2. **Attacker Action**:
     - On a separate machine on the same network, use a tool like `netcat` (`nc`) or `telnet` to establish a TCP connection to the lab equipment's IP address and port used by the Py-Lab-HAL application.
     - Using the documentation or by reverse engineering (if necessary), identify valid commands for the lab equipment (e.g., SCPI commands for a power supply, or custom commands for other equipment).
     - Send a command through the `netcat` connection to the lab equipment, for example, a command to set the voltage of a DC power supply if that is the equipment being used.
     - Example using `netcat` to send SCPI command to a DC Power Supply (assuming the command is `VOLT 10`):
       ```bash
       nc <lab_equipment_ip> <lab_equipment_port>
       VOLT 10<CR><LF>
       ```
  3. **Expected Result**:
     - The lab equipment executes the command sent by the attacker through `netcat`, demonstrating unauthorized control. For example, if a voltage setting command was sent, the output voltage of the power supply should change to the attacker-specified value.
     - There should be no authentication prompt or error message indicating access denial.
     - This test case will prove that an external attacker can directly control the lab equipment through the network socket without any authentication, validating the vulnerability.