- Vulnerability Name: Uncontrolled Robot Movement
- Description: A malicious actor can modify the CircuitPython code to directly control the robot's servos in an unintended and potentially harmful way. By altering the code responsible for controlling the servo motors, an attacker can bypass the intended line following or obstacle avoidance behaviors and command the robot to move erratically. For example, an attacker could set extreme servo throttle values, causing the robot to move at full speed in random directions, potentially damaging itself or its surroundings. This is achieved by modifying the Python scripts (e.g., `5_line_follower.py`, `6_sonar_line_follower.py`, or even the default `code.py`) on the `CIRCUITPY` drive.

    Steps to trigger the vulnerability:
    1. Access the `CIRCUITPY` drive of the robot's microcontroller by connecting it to a computer via USB after it has been flashed with CircuitPython.
    2. Navigate to the `code` directory on the `CIRCUITPY` drive.
    3. Modify any of the Python files (e.g., `code.py`, `5_line_follower.py`, `6_sonar_line_follower.py`) to directly set servo throttle values to extreme or arbitrary values, bypassing the intended control logic. For example, in `5_line_follower.py`, replace the line following logic with code that sets `servo_left.throttle = 1.0` and `servo_right.throttle = 1.0` within the `while True` loop.
    4. Save the modified file. The microcontroller will automatically detect the change and run the new code upon the next reset or power cycle.
    5. Power on or reset the robot. The robot will now execute the modified code and move according to the attacker's malicious commands.

- Impact: The robot can move erratically and unpredictably. This uncontrolled movement can lead to several negative consequences:
    - Physical damage to the robot itself, such as motor burnout due to continuous full-speed operation, broken gears, or damage to the chassis from collisions.
    - Damage to the robot's environment, including collisions with objects, furniture, or other equipment in the vicinity.
    - The robot could fall off elevated surfaces like tables, leading to damage upon impact.
    - In an educational setting, erratic robot behavior can be disruptive and potentially unsafe, especially if students are not expecting or prepared for it.

- Vulnerability Rank: High. The potential for physical damage to the robot and its surroundings, combined with the ease of exploitation, makes this a high-risk vulnerability in the context of an educational robot kit.

- Currently Implemented Mitigations: None. The provided code examples are designed for educational purposes and lack any security features to prevent malicious code modification or execution. The system operates on the assumption that users will only load trusted code.

- Missing Mitigations:
    - Code signing or verification: Implementing a mechanism to verify the integrity and authenticity of the CircuitPython code before execution would prevent the robot from running modified, potentially malicious code. This could involve cryptographic signatures and a secure boot process.
    - Sandboxing or privilege separation: Restricting the capabilities of the CircuitPython code to limit its ability to directly control hardware components like servos with extreme values could mitigate the impact of malicious code. However, this might be complex to implement in CircuitPython on a microcontroller.
    - Rate limiting or input validation on servo commands: Implementing checks within the firmware or CircuitPython libraries to limit the range and rate of change of servo commands could prevent extreme movements. However, this would require modifications beyond the provided example code.
    - Physical safeguards:  While not a code-level mitigation, physical safeguards such as operating the robot in a contained area, using soft surfaces, or having emergency stop mechanisms could reduce the potential for damage.

- Preconditions:
    - Physical access to the robot's microcontroller via USB to modify the files on the `CIRCUITPY` drive. This access is assumed as part of the described attack vector, where a malicious actor could modify the code before it is copied to the microcontroller.
    - The robot must be powered on and running the modified CircuitPython code.

- Source Code Analysis:
    - File: `/code/code/5_line_follower.py` (and other servo control examples like `4_servo_blink.py`, `6_sonar_line_follower.py`, `7_button.py`)
    - The code directly controls servo motors using the `adafruit_motor.servo` library.
    - In `5_line_follower.py`, the lines `servo_left.throttle = 0.1 * line_left.value` and `servo_right.throttle = -0.15 * line_right.value` control the servos based on sensor input.
    - **Vulnerability:** An attacker can easily modify these lines or replace the entire `while True` loop to set arbitrary `throttle` values. For instance, replacing the loop with:
      ```python
      while True:
          servo_left.throttle = 1.0
          servo_right.throttle = 1.0
      ```
      will command both servos to full forward speed continuously.
    - The `servo.throttle` property accepts values in the range of -1.0 to +1.0, representing full reverse to full forward speed. There are no built-in checks in the example code or the `adafruit_motor` library usage shown to limit these values or prevent rapid changes.
    - The code directly translates potentially attacker-controlled code into physical actions of the robot without any validation or security checks.

- Security Test Case:
    1. **Prepare the malicious code:**
        - Take a copy of the `5_line_follower.py` file (or any file that controls servos, or even `code.py` if you are starting fresh).
        - Modify the code within the `while True:` loop to directly and maximally drive the servos forward. Replace the original loop content with:
          ```python
          while True:
              servo_left.throttle = 1.0
              servo_right.throttle = 1.0
          ```
        - Save the modified file as `code.py` on your local computer.
    2. **Flash the malicious code to the robot:**
        - Connect the Xiao RP2040 microcontroller to your computer while holding the "BOOT" button to enter bootloader mode.
        - Copy the modified `code.py` file to the `CIRCUITPY` drive. This will replace the existing `code.py` or any other Python file that might be set to run by default.
        - Safely eject the `CIRCUITPY` drive and disconnect the USB cable. The microcontroller will reset and run the new code.
    3. **Observe the robot's behavior:**
        - Power on the robot (if it's not already powered).
        - Observe the robot's movement. It should immediately start moving forward at full speed. If placed on a surface with sufficient space, it will continue to move forward until it collides with something, falls off an edge, or power is removed. The line sensors will be completely ignored, and the robot will not perform line following.
    4. **Expected outcome:** The robot moves straight forward at maximum speed, demonstrating uncontrolled robot movement due to the malicious code modification. This proves the vulnerability as the attacker successfully overrode the intended robot behavior to cause potentially damaging, uncontrolled action.