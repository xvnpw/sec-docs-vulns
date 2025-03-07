### Vulnerability List

- Vulnerability Name: **XC9500XL Breakout Board v1 Power Pin Errata**
- Description: The v1 version of the XC9500XL breakout board has an errata where the 5V and 0V pins are marked incorrectly on the power header. If a user builds the v1 board and connects power according to the markings on the PCB, they will reverse the power supply, potentially damaging the CPLD or the connected vintage computer system if the board is used in an expansion.
- Impact: **High**. Reverse polarity can damage electronic components, potentially destroying the CPLD or damaging the vintage computer system it is connected to.
- Vulnerability Rank: **High**
- Currently Implemented Mitigations: The vulnerability is documented in the `xc9500xl_44_breakout/README.md` file under the "Errata" section.
- Missing Mitigations:
    - **Hardware Mitigation**: Revision v2 of the board should correct the PCB marking error. Making v2 the primary and recommended design would mitigate this.
    - **Software/Documentation Mitigation**: Prominently display the errata in the README.md and potentially add a warning to the build instructions.
- Preconditions: User building the v1 version of the `xc9500xl_44_breakout` board. User not carefully checking the schematic and relying only on PCB markings.
- Source Code Analysis:
    - File: `/code/xc9500xl_44_breakout/README.md`
    - Content:
    ```
    ## Errata

    v1 has 5V and 0V marked the wrong way around on the power pins at the top of
    the board.
    ```
    - The `README.md` file clearly states the vulnerability in the "Errata" section. This is a documentation mitigation, but not a prevention of the issue if the user doesn't read it carefully. The PCB design files for v1 are still present in the repository, which could lead to users building the flawed version.
- Security Test Case:
    1. Download the v1 PCB design files for `xc9500xl_44_breakout`.
    2. Fabricate the v1 PCB.
    3. Connect a power supply to the power header using the markings on the PCB (5V to "5V" and 0V to "0V").
    4. Measure the voltage at the CPLD's power pins. The voltage will be reversed, with negative voltage applied to the intended positive rail and vice versa.
    5. Power on a CPLD on the board in this reversed polarity configuration. Observe if the CPLD is damaged or malfunctions.
    6. Connect the v1 board to a vintage computer expansion port with reversed polarity. Observe if the vintage computer is damaged or malfunctions.

- Vulnerability Name: **32kb_flash_cartridge pcb-mini PCB Error**
- Description: The `pcb-mini` version of the 32kb_flash_cartridge has a PCB design error where "several data lines are shorted to ground". If a user builds the `pcb-mini` board, the shorted data lines can cause malfunction of the cartridge and potentially damage the Electron computer when plugged in.
- Impact: **High**. Shorted data lines can cause unpredictable behavior, data corruption and potentially damage the Acorn Electron hardware due to electrical faults.
- Vulnerability Rank: **High**
- Currently Implemented Mitigations: The vulnerability is documented in the `32kb_flash_cartridge/README.md` file, stating "Mini PCB built but had a PCB error.".
- Missing Mitigations:
    - **Hardware Mitigation**: Remove or clearly mark the `pcb-mini` design as broken and discourage its use. Provide the `pcb-standard` design as the recommended option. Correct the PCB design for `pcb-mini` and release a fixed version.
    - **Software/Documentation Mitigation**: Prominently display a warning in the README.md for `pcb-mini` and potentially remove the design files to prevent accidental fabrication.
- Preconditions: User building the `pcb-mini` version of the `32kb_flash_cartridge`. User unaware of the PCB error.
- Source Code Analysis:
    - File: `/code/32kb_flash_cartridge/README.md`
    - Content:
    ```
    - [pcb-mini](pcb-mini/): This is designed to just barely protrude from
      the Plus 1 when plugged in.  Unfortunately I forgot to re-pour the
      power and ground planes before generating gerbers to send off to the
      fab, and several data lines are shorted to ground in the units that
      I have.
    ```
    - The `README.md` file clearly documents the PCB error in the `pcb-mini` design. This serves as documentation mitigation but doesn't prevent users from fabricating the flawed design.
- Security Test Case:
    1. Download the PCB design files for `32kb_flash_cartridge/pcb-mini`.
    2. Fabricate the `pcb-mini` PCB.
    3. Using a multimeter in continuity mode, check for shorts between data lines and ground on the fabricated PCB. Confirm that "several data lines are shorted to ground".
    4. Program a flash chip with test ROM image.
    5. Plug the `pcb-mini` cartridge into an Acorn Electron.
    6. Power on the Acorn Electron. Observe if the Electron malfunctions, crashes, or exhibits data corruption due to the shorted data lines on the cartridge.

- Vulnerability Name: **32kb_flash_cartridge pcb-mini Power and Ground Plane Error**
- Description: The `pcb-mini` version of the 32kb_flash_cartridge has a PCB design error where power and ground planes are not properly poured. This can lead to inadequate power and ground distribution, potentially causing unreliable operation of the cartridge and the Acorn Electron. While not directly causing physical damage, unreliable operation due to power issues can corrupt data or cause system instability.
- Impact: **Medium**. Unreliable operation, data corruption, system instability. While less severe than immediate physical damage, it can still negatively impact the user experience and potentially lead to data loss on vintage systems.
- Vulnerability Rank: **Medium**
- Currently Implemented Mitigations: The vulnerability is documented in the `32kb_flash_cartridge/README.md` file, stating "I forgot to re-pour the power and ground planes before generating gerbers to send off to the fab".
- Missing Mitigations:
    - **Hardware Mitigation**: Similar to the data line short vulnerability, remove or clearly mark the `pcb-mini` design as broken. Provide the `pcb-standard` design as the recommended option. Correct the PCB design for `pcb-mini` and release a fixed version.
    - **Software/Documentation Mitigation**: Prominently display a warning in the README.md for `pcb-mini` and potentially remove the design files.
- Preconditions: User building the `pcb-mini` version of the `32kb_flash_cartridge`. User unaware of the power and ground plane error.
- Source Code Analysis:
    - File: `/code/32kb_flash_cartridge/README.md`
    - Content:
    ```
    - [pcb-mini](pcb-mini/): ... Unfortunately I forgot to re-pour the
      power and ground planes before generating gerbers to send off to the
      fab, ...
    ```
    - The `README.md` file acknowledges the lack of proper power and ground planes, indicating a potential design flaw.
- Security Test Case:
    1. Download the PCB design files for `32kb_flash_cartridge/pcb-mini`.
    2. Fabricate the `pcb-mini` PCB.
    3. Visually inspect the PCB gerber files for `pcb-mini` and compare to `pcb-standard`. Confirm the absence of proper power and ground planes in `pcb-mini`.
    4. Assemble a `pcb-mini` cartridge.
    5. Program a flash chip with a test ROM image that performs extensive read/write operations to the SD card or emulated storage.
    6. Plug the `pcb-mini` cartridge into an Acorn Electron.
    7. Run the test ROM on the Acorn Electron and monitor for system instability, crashes, or data corruption during prolonged operation, which could be attributed to inadequate power and ground distribution.

- Vulnerability Name: **XC9536XL-10VQG44 or XC9572XL-10VQG44 CPLD Breakout Board Errata v1 - Incorrect Power Pin Labels**
- Description: The v1 version of the XC9500XL-xxVQG44 breakout board has an errata where the 5V and 0V labels are swapped on the power pins. If users follow these incorrect labels during assembly, they may inadvertently reverse the power supply, potentially damaging the CPLD or any connected circuitry.
- Impact: **High**. Reversed power supply can lead to component damage or failure, potentially destroying the CPLD or connected vintage computer components.
- Vulnerability Rank: **High**
- Currently Implemented Mitigations: The errata is documented in the `xc9500xl_44_breakout/README.md` file within the "Errata" section.
- Missing Mitigations:
    - **Hardware Mitigation**:  Version v2 should correct this marking error. Emphasize and promote the use of v2 design files.
    - **Documentation Mitigation**: Clearly and prominently display the errata in the README.md, potentially with visual warnings, and reiterate the correct polarity in assembly instructions.
- Preconditions: User assembling the v1 version of the `xc9500xl_44_breakout` board and relying solely on the PCB silkscreen labels for power connection without verifying against the schematic.
- Source Code Analysis:
    - File: `/code/xc9500xl_44_breakout/README.md`
    - Content:
    ```
    ## Errata

    v1 has 5V and 0V marked the wrong way around on the power pins at the top of
    the board.
    ```
    - The `README.md` file explicitly mentions the reversed polarity issue in v1, serving as a documentation-based mitigation. However, the risk remains for users who overlook this errata or only refer to the PCB markings.
- Security Test Case:
    1. Obtain the v1 PCB design files for `xc9500xl_44_breakout`.
    2. Fabricate the v1 PCB.
    3. Connect a power supply to the board using the silkscreen labels for polarity (5V to "5V" and 0V to "0V").
    4. Measure the voltage at the CPLD's power pins to confirm reversed polarity.
    5. Power on a CPLD on the v1 board with reversed polarity. Observe for component damage or malfunction.
    6. Connect the v1 board with reversed polarity to a vintage computer system (if applicable to its intended use). Observe for damage or malfunction in the vintage computer.

- Vulnerability Name: **Master Updateable MegaROM Model B Modification Instructions - Potential Damage**
- Description: The `master_updateable_megarom/README.md` provides instructions for modifying the MegaROM board for use in a BBC Model B. These instructions involve cutting pins and soldering jumper wires to redirect signals. Incorrect execution of these instructions, particularly connecting pin 1 and 27 to IC76 pins 12 and 11 respectively, and pin 20 to cpld_JP1 without careful verification, could lead to miswiring and potential damage to the MegaROM board or the BBC Model B motherboard.
- Impact: **Medium**. Miswiring can cause malfunction of the MegaROM board and potentially damage the BBC Model B motherboard, requiring repair or replacement of components.
- Vulnerability Rank: **Medium**
- Currently Implemented Mitigations: The modification instructions are provided with some warnings in the `master_updateable_megarom/README.md` file.
- Missing Mitigations:
    - **Documentation Mitigation**:  Emphasize the risk of damage in the modification instructions. Add clearer warnings and visual aids (diagrams) to highlight critical steps and potential miswiring hazards. Recommend thorough verification with a multimeter before powering on.
    - **Hardware Mitigation**: While not fully mitigating miswiring, adding protection diodes or current-limiting resistors in critical paths of the modification could reduce the risk of damage from minor wiring errors. However, this might complicate the design and is not currently implemented.
- Preconditions: User attempting to modify the `master_updateable_megarom` board for use in a BBC Model B and incorrectly following the modification instructions. User not carefully verifying the wiring before applying power.
- Source Code Analysis:
    - File: `/code/master_updateable_megarom/README.md`
    - Content: The "Modification for use in a pair of Model B ROM sockets" section in the `README.md` provides step-by-step instructions, but relies on user's careful execution and verification.
    ```
    Modification for use in a pair of Model B ROM sockets
    -----------------------------------------------------

    The MegaROM also works when installed in a Model B! ...

    ### Modification instructions

    This board can also be used to fill two of the ROM sockets on a Model B, and
    provide 8 16kB flash banks.  Some modifications are required.

    The Master 128's MOS ROM socket differs from the Model B's ROM sockets in the
    following ways:

    - Pin 1 is A15 on the Master, and 5V on the Model B
    - Pin 27 is A14 on the Master, and 5V on the Model B
    - Pin 22 is A16 on the Master, and /OE on the Model B
    - Pin 20 is /CE on both, but is always tied low on the Master and is selectable
      on the BBC, and is left disconnected on this board.

    Wiring it up like this should work:

    - Cut pin 1 and solder a jumper wire from the top of the pin to IC76 pin 12.
    - Cut pin 27 and solder a jumper wire from the top of the pin to IC76 pin 11.
    - Solder a jumper wire from the top of pin 20 to the cpld_JP1 pin.
    - Connect a jumper wire from pin 20 on the adjacent socket to the cpld_JP0 pin.

    Changes are required to the Verilog also: ...
    ```
    - The instructions, while detailed, are prone to user error during physical modification, especially for users not experienced with electronics modifications.
- Security Test Case:
    1. Obtain a `master_updateable_megarom` board and a BBC Model B.
    2. Intentionally miswire the modification instructions, for example, swap connections for pin 1 and pin 27, or connect pin 20 to the wrong jumper pin.
    3. Install the miswired MegaROM board into the BBC Model B.
    4. Power on the BBC Model B. Observe if the BBC Model B malfunctions, fails to boot, or shows signs of electrical stress (smoke, heat) indicating potential damage.
    5. Check the MegaROM board for damage or malfunction after the test.