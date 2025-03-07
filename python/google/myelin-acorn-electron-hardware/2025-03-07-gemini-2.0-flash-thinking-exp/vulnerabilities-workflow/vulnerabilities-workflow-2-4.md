### Vulnerability Name: Keystroke Injection via USB Serial Interface

* Description:
    1. An attacker gains control of the host computer connected to the "emulated_keyboard" Pro Micro via USB.
    2. The attacker crafts a malicious payload consisting of keystroke commands according to the protocol implemented in `prototype_keyboard_sender.py`.
    3. The attacker sends this payload through the USB serial interface to the Pro Micro.
    4. The Pro Micro firmware, running `prototype_firmware/prototype_firmware.ino`, receives the payload and interprets it as keyboard input.
    5. The Pro Micro communicates with the CPLD, running the design from `prototype_cpld/prototype_cpld.vhd`, via SPI to simulate keystrokes to the BBC Master 128.
    6. The BBC Master 128 interprets these injected keystrokes as legitimate keyboard input, potentially leading to execution of arbitrary commands or system compromise.

* Impact:
    * An attacker can inject arbitrary keystrokes into a BBC Master 128 via the emulated keyboard, potentially bypassing intended system security measures.
    * This could allow for unauthorized command execution, data modification, or installation of malicious software on the retro system.
    * The impact is significant as it allows control over a system that is expected to be isolated or controlled through its original keyboard interface.

* Vulnerability Rank: High

* Currently Implemented Mitigations:
    * None. The provided code implements the basic functionality of keyboard emulation without any security considerations.

* Missing Mitigations:
    * **Input Validation and Sanitization**: The Pro Micro firmware should validate and sanitize the incoming serial data to ensure it conforms to the expected keystroke command structure and prevent injection of malicious commands.
    * **Authentication/Authorization**: Implement a mechanism to authenticate or authorize the host computer sending keystrokes, preventing unauthorized injection from malicious sources.
    * **Rate Limiting**: Implement rate limiting on keystroke processing to mitigate potential abuse or denial-of-service attempts.
    * **Secure Communication Protocol**: Consider using a more secure communication protocol than plain serial, if feasible for the retro system context.

* Preconditions:
    * A user must build and deploy the "emulated_keyboard" hardware and firmware as described in the `README.md`.
    * An attacker must gain control of the computer connected to the Pro Micro via USB serial.

* Source Code Analysis:
    1. **`prototype_keyboard_sender.py`**: This Python script uses `pygame` to capture keyboard events and sends them over serial. It defines the basic protocol for sending keystrokes.
    ```python
    def set_keys(self, key1, key2, shift_down, ctrl_down, break_down):
        msg = '*%c%c%c#' % (
            key1,
            key2,
            (0x80 if shift_down else 0) | (0x40 if ctrl_down else 0) | (0x20 if break_down else 0),
        )
        self.ser.write(msg)
        print(repr(self.ser.read(1)))
    ```
    The `set_keys` function formats the keystroke data into a simple string message starting with `*` and ending with `#`.  There is no input validation or security mechanism in this sender script.

    2. **`prototype_firmware/prototype_firmware.ino`**: This Arduino code receives serial data and parses it to control the CPLD via SPI.
    ```arduino
    void serialEvent() {
      while (Serial.available()) {
        char inChar = (char)Serial.read();
        if (receivingChars) {
          if (inChar == endMarker) {
            receivedChars[dataIndex] = '\0';
            receivingChars = false;
            parse_message();
          }
          else if (dataIndex < numChars) {
            receivedChars[dataIndex] = inChar;
            dataIndex++;
          }
        }
        else if (inChar == startMarker) {
          receivingChars = true;
          dataIndex = 0;
        }
      }
    }
    ```
    The `serialEvent` function reads serial data until it finds an `endMarker` (`#`). It assumes that any data between `startMarker` (`*`) and `endMarker` is a valid keystroke command.

    ```arduino
    void parse_message() {
      if (receivedChars[0] == '*') {
        key1 = receivedChars[1];
        key2 = receivedChars[2];
        flags = receivedChars[3];
        update_keyboard();
      }
    }
    ```
    The `parse_message` function directly extracts `key1`, `key2`, and `flags` from the received serial data without any validation. This allows an attacker to inject arbitrary byte values that will be directly interpreted as keystrokes by the `update_keyboard()` function and forwarded to the CPLD.

    3. **`prototype_cpld/prototype_cpld.vhd`**: This VHDL code running on the CPLD receives SPI commands from the Pro Micro and simulates keyboard signals for the BBC Master 128. The code is designed to directly translate the SPI commands into keyboard signals without any security checks.

* Security Test Case:
    1. Build and upload the `prototype_firmware` to a Pro Micro, and program the `prototype_cpld` design to a CPLD connected as described in `emulated_keyboard/README.md`.
    2. Connect the Pro Micro to a host computer and the CPLD to a BBC Master 128.
    3. On the host computer, use a serial communication tool (e.g., `PuTTY`, `screen`, `minicom`).
    4. Open a serial connection to the Pro Micro's serial port.
    5. Send a crafted serial payload designed to execute a command on the BBC Master 128. For example, to execute `*RUN`, send the following serial data (corresponding to 'R', 'U', 'N' and ENTER keystrokes, along with necessary flags):
        * Payload (ASCII representation for clarity): `*RUN\r#`
        * Payload (Hex representation): `2A 52 55 4E 0D 23`
    6. Observe the BBC Master 128. If the vulnerability is present, the BBC Master 128 should execute the injected `*RUN` command, demonstrating arbitrary keystroke injection.  Further more complex and potentially harmful commands can be injected to confirm the full impact.