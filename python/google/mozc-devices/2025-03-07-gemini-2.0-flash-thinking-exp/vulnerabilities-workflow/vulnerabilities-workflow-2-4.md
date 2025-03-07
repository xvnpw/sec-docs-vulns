### Vulnerability List

- Vulnerability Name: Use of Pre-built Firmware Binaries
- Description:
  - The build instructions for the "Gboard double sided version" keyboard project recommend flashing a pre-built firmware binary (`firmware/prebuilt/mozc.elf`).
  - This binary is provided without instructions for building it from source, forcing users to rely on a pre-compiled binary from an untrusted source.
  - A malicious actor with control over the repository or distribution channels could replace this pre-built binary with a compromised version.
  - This compromised firmware could contain malicious functionalities such as keylogging, backdoors for remote access, or other forms of malware.
  - Users who follow the official build instructions are unknowingly instructed to flash this potentially malicious binary onto their DIY keyboard's microcontroller.
- Impact:
  - High. Flashing a malicious firmware binary can lead to complete compromise of the user's keystrokes and potentially other sensitive data transmitted through the keyboard.
  - Attackers could gain access to passwords, personal messages, financial information, and any other text entered using the keyboard.
  - In the case of a backdoor, attackers could potentially gain further control over the user's system depending on the firmware implementation and any network connectivity enabled by the device.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
  - None. The project provides pre-built firmware without any integrity checks or alternative build methods in the `mozc-doublesided` project.
- Missing Mitigations:
  - Provide instructions and scripts to build the firmware from source code. This would allow users to compile the firmware themselves, ensuring they are using a trusted codebase.
  - Implement checksums or digital signatures for the pre-built binaries. This would allow users to verify the integrity and authenticity of the pre-built firmware before flashing it.
  - Host the source code of the firmware in the repository, alongside the pre-built binaries. This increases transparency and allows security-conscious users to inspect the code.
- Preconditions:
  - The user chooses to build the "Gboard double sided version" keyboard.
  - The user follows the official build instructions provided in the `README.md` file.
  - The user proceeds to the "Firmware upload" step and downloads and flashes the provided pre-built `firmware/prebuilt/mozc.elf` binary.
- Source Code Analysis:
  - In the file `/code/mozc-doublesided/README.md`, the "Firmware upload" section clearly instructs the user to:
    - "Next, let's burn the prebuilt firmware."
    - "you need to write the `Option bytes`... ensure the bit is unchecked before pushing the `Apply` button."
    - "Next, you will go to the `Erasing & Programming` section to burn the prebuilt firmware, `firmware/prebuilt/mozc.elf`."
  - This sequence of instructions directly leads the user to download and flash a pre-compiled binary without offering source code compilation as an alternative or any security verification steps for the binary itself.
  - No corresponding source code for generating `firmware/prebuilt/mozc.elf` is explicitly provided or linked in the `mozc-doublesided` directory. The `firmware/` directory primarily contains STM32CubeIDE project files, suggesting source code exists but isn't directly presented for independent building by the user following the README.
- Security Test Case:
  1. **Setup:**
     - Set up a controlled environment for testing, ideally a virtual machine or isolated system to prevent potential harm from malicious firmware.
     - Obtain a clean copy of the project repository.
  2. **Attack Scenario:**
     - As an attacker, replace the legitimate pre-built firmware binary `code/mozc-doublesided/firmware/prebuilt/mozc.elf` with a malicious ELF binary. This malicious binary should be designed to simulate keylogging (e.g., by storing keystrokes in memory or sending them to a network listener if possible in the simulated environment).
  3. **User Action:**
     - As a user, follow the build instructions in `/code/mozc-doublesided/README.md` up to the "Firmware upload" step.
     - Use the provided instructions to flash the (now malicious) `firmware/prebuilt/mozc.elf` onto a test microcontroller board (STM32F042F4P6 or similar).
     - Simulate keyboard usage by sending input through the keyboard (if the test environment allows) or by other means to trigger the keylogging functionality in the malicious firmware.
  4. **Verification:**
     - Check if the simulated keylogging functionality in the malicious firmware is executed after flashing and using the keyboard.
     - For example, verify if keystrokes are being logged in memory, sent to a network listener, or stored in a file system accessible to the test environment, depending on the design of the malicious firmware.
  5. **Expected Result:**
     - The test should demonstrate that by simply following the official instructions, a user can be easily tricked into flashing and running malicious pre-built firmware, confirming the vulnerability. The malicious firmware will successfully execute its keylogging or other malicious functionalities.