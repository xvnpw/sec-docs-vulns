- Vulnerability name: Unsigned Firmware Flashing
- Description: The project provides instructions to build and flash firmware onto microcontrollers for DIY keyboards. However, there is no mechanism to ensure the firmware's integrity or authenticity. An attacker can create a malicious firmware image and trick a user into flashing it onto their device. This can be achieved by distributing the malicious firmware through various channels, such as a compromised repository, a fake build guide, or social engineering.
- Impact: If a user flashes a malicious firmware, the attacker gains complete control over the keyboard's functionality. This allows for keystroke injection attacks, where the attacker can send arbitrary keystrokes to the user's computer without their knowledge or consent. This can lead to various harmful outcomes, including data theft, execution of arbitrary commands, and installation of malware.
- Vulnerability rank: Critical
- Currently implemented mitigations: None. The project provides no mechanisms for firmware signing or verification.
- Missing mitigations: Firmware signing and verification should be implemented. The firmware flashing process should include a step to verify the signature of the firmware image before flashing. Secure boot mechanisms on the microcontroller should be enabled if available. Documentation should warn users about the risks of flashing firmware from untrusted sources.
- Preconditions:
    - The attacker needs to create a malicious firmware image.
    - The attacker needs to convince a user to download and flash this malicious firmware onto their DIY keyboard.
    - The user must follow the project's instructions for flashing firmware, using tools like STM32CubeProgrammer (for `mozc-doublesided`).
- Source code analysis:
    1. The `mozc-doublesided/README.md` file provides instructions for flashing firmware.
    2. Under "Firmware upload", it guides the user to use STM32CubeProgrammer to flash `firmware/prebuilt/mozc.elf`.
    3. There are no steps mentioned for verifying the authenticity or integrity of `mozc.elf`.
    4. The firmware is provided as a pre-built binary (`.elf`), so users are expected to flash this binary directly without any checks.
    5. No code in the provided files implements firmware signing or verification.
- Security test case:
    1. **Prepare malicious firmware:** Modify the firmware source code (available in the repository for some keyboard versions, e.g., `mozc-doublesided/firmware`) to include keystroke injection functionality. For example, the firmware could be modified to send "evil command" when a specific key combination is pressed, or periodically send keystrokes. Compile this modified firmware to produce a malicious `mozc.elf` (or the relevant binary format for other keyboard projects).
    2. **Create a fake guide/distribute malicious firmware:** Create a fake online guide or repository that hosts the malicious firmware (`mozc.elf`). Alternatively, directly share the malicious `mozc.elf` with a target user, perhaps through social engineering, disguised as an update or a necessary component for building the keyboard.
    3. **Instruct user to flash malicious firmware:** Guide the user to follow the original project's firmware flashing instructions, but point them to the malicious `mozc.elf` instead of the legitimate one. For `mozc-doublesided`, this involves using STM32CubeProgrammer and flashing the provided `mozc.elf` to the microcontroller.
    4. **Test keystroke injection:** After the user flashes the malicious firmware and connects the DIY keyboard to their computer, observe if the injected keystrokes are sent to the computer. For instance, if the malicious firmware was designed to type "evil command", check if this text appears in a text editor or command prompt when the compromised keyboard is connected and potentially when a trigger key (or time) is activated.