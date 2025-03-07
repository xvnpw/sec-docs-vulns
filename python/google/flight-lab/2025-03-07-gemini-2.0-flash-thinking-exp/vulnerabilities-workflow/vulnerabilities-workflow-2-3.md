- Vulnerability name: Missing Input Validation in Component Status Updates
- Description:
  - Step 1: An attacker compromises a client machine or simulates a malicious client capable of sending gRPC messages to the controller server.
  - Step 2: The attacker crafts a malicious `UpdateStatus` gRPC message. This message is designed to include crafted `component_status` data with unexpected or out-of-range values. For example, if a component represents airspeed, the attacker sets the airspeed value to an extremely large or negative number, or injects special characters.
  - Step 3: The malicious client sends this crafted `UpdateStatus` message to the controller server via gRPC on the designated port (default port 9000).
  - Step 4: The `ControlService` running on the controller server receives the `UpdateStatus` message.
  - Step 5: Within `ControlService.UpdateStatus`, the server processes the message and updates the `system_config` with the received component status values. Critically, this update process is performed without proper validation of the content of the `component_status` data. The server only checks if the machine and component names are valid and present in the system configuration.
  - Step 6: The system configuration, now potentially containing these invalid status values, is used to drive the flight simulation. It is assumed that these status values are eventually transmitted to and utilized by the firmware controlling the hardware components of the simulator.
  - Step 7: If the firmware, upon receiving these status values, does not perform adequate input validation, it becomes vulnerable to memory corruption. For instance, processing extremely large numbers or unexpected characters could lead to buffer overflows or other memory-related errors within the firmware.
  - Step 8: By successfully exploiting this lack of validation, an attacker can potentially induce memory corruption in the firmware, leading to unpredictable behavior, system crashes, or, in a worst-case scenario, gain control over the flight simulation system's firmware and consequently the physical simulator itself.
- Impact:
  - Memory corruption in the firmware of the flight simulation system.
  - Potential for unauthorized control over the flight simulation system.
  - System instability, leading to crashes or unpredictable and erroneous simulation behavior.
  - Possible exploitation to bypass security measures and manipulate the simulation environment for malicious purposes.
- Vulnerability rank: High
- Currently implemented mitigations:
  - None. The source code analysis of `ControlService.UpdateStatus` in `/code/controller/controller.py` reveals no input validation on the content of the `component_status` messages. The server only validates the existence of machine and component names, not the data itself.
- Missing mitigations:
  - Implementation of robust input validation within the `ControlService.UpdateStatus` function on the server side. This validation should include checks for:
    - Range validation: Ensuring that received status values fall within expected and safe ranges for each component type (e.g., airspeed, heading, etc.).
    - Format validation: Verifying that the format of the received data conforms to expected types and structures, guarding against injection of unexpected data types or special characters.
  - Implementation of input validation within the firmware itself. Regardless of server-side validation, the firmware should independently validate all incoming data from any source, including the controller server, before processing or utilizing it to control hardware or simulation parameters. This defense-in-depth approach is critical to prevent memory corruption at the firmware level, even if validation is bypassed or missed at higher levels.
- Preconditions:
  - The attacker must have the ability to send gRPC messages to the controller server. This can be achieved by:
    - Compromising a machine that is already authorized to act as a client in the Flight Lab system.
    - Simulating a malicious client on the network if the gRPC control service port (default 9000) is exposed and accessible from the attacker's network.
- Source code analysis:
  - File: `/code/controller/controller.py`
  - Function: `ControlService.UpdateStatus(self, machine_status, context)`
  - Step-by-step analysis:
    1. The `UpdateStatus` function is invoked when the gRPC server receives an `UpdateStatus` message from a client.
    2. The function first attempts to locate the machine within the `_system_config.machines` list based on the `machine_status.name`. If the machine is not found, a warning is logged, and the function returns.
    3. The code then iterates through each `component_status` within the received `machine_status.component_status` list.
    4. For each `component_status`, it attempts to find the corresponding component in the `machine.components` list based on `component_status.name`. If the component is not found, a warning is logged, and the loop continues to the next `component_status`.
    5. If both machine and component are found, an informational log message is generated, indicating a status update.
    6. The code retrieves the actual status value from the `component_status` based on its 'kind' (e.g., `projector_status`, `app_status`).
    7. It then retrieves the settings of the corresponding component from the `system_config`, again based on its 'kind'.
    8. Finally, it updates the `settings.status` and `component.status` with the received status value.
    9. **Crucially, there is no validation performed on the `status` value itself before it is assigned to `settings.status`. The code directly assigns the received value without checking its range, format, or validity.**
  - Visualization: No specific visualization needed for this code walkthrough. The vulnerability is evident in the lack of validation before assignment in the `UpdateStatus` function.
- Security test case:
  - Step 1: Deploy the Flight Lab system, ensuring both the controller server and at least one client are running. Identify the IP address of the server.
  - Step 2: Install the `protobuf` and `grpc` Python libraries in a testing environment that can communicate with the controller server.
  - Step 3: Create a Python script to act as a malicious gRPC client. This script will:
    - Import necessary gRPC and protobuf libraries for `sim_proxy_pb2`, `sim_proxy_pb2_grpc`, `controller_pb2`, and `controller_pb2_grpc` (you'll need to generate these from the provided `.proto` files if they aren't readily available as Python modules).
    - Establish an insecure gRPC channel to the controller server's IP address and port 9000.
    - Create a gRPC stub for the `ControlService`.
    - Construct an `UpdateStatus` request message (`controller_pb2.MachineStatus`). This message should include:
      - `machine_status.name`: Set to the name of a valid machine from your `config.protoascii` (e.g., 'client').
      - `component_status`: Create a `controller_pb2.ComponentStatus` message within this list.
        - `component_status.name`: Set to the name of a component that handles numerical data (you'll need to inspect your `config.protoascii` to identify such a component, e.g., a hypothetical 'airspeed_indicator').
        - Set the status value within `component_status` to an out-of-range value. For example, if it's an `app_status`, you might try setting a string value when an integer is expected, or a very large integer if numerical. If it's a `projector_status` which is an enum, try setting an integer outside the enum range. A safe test would be to try sending a very long string as status. For example, if component type is 'app', you would set `component_status.app_status.status = "A" * 2000` (assuming app status is string, adjust if it's different type - if it's enum, try invalid enum number).
    - Use the gRPC stub to call `UpdateStatus` on the server, sending the crafted `MachineStatus` message.
  - Step 4: Execute the malicious client script.
  - Step 5: Monitor the controller server logs for errors or warnings. Observe the behavior of the Flight Lab system. Check for any signs of instability, crashes, or unexpected behavior. If you have access to firmware logs or debugging tools, monitor those for indications of memory corruption or errors when processing the status update.
  - Step 6: Expected outcome: If the vulnerability exists, sending a crafted status update with invalid data may lead to errors on the server side (though unlikely given the lack of server-side validation), or, more critically, if this invalid data propagates to the firmware, it may cause firmware crashes or erratic behavior. A successful test would demonstrate the system's vulnerability to accepting and propagating invalid component status data. Note that without firmware source code or direct firmware access, it might be challenging to definitively confirm memory corruption, but observing system instability after sending invalid data would strongly suggest a vulnerability.