- Vulnerability Name: CPU Socket Overvoltage
  - Description: An attacker could modify the `cpu_socket_expansion` hardware design to incorrectly route the 5V power supply to a pin on the CPU socket intended for a 3.3V signal or ground. If a user builds this malicious design and plugs it into their Acorn Electron or BBC computer, the overvoltage could cause permanent damage to the CPU or other motherboard components. This could be achieved by altering the PCB layout or schematic files to create a direct connection between a 5V pin and a pin connected to the CPU's 3.3V rail or a ground pin.
  - Impact: Critical hardware damage to the retro computer, potentially rendering it unusable. Damage could include CPU burnout, motherboard trace damage, or failure of other components.
  - Vulnerability Rank: Critical
  - Currently implemented mitigations: None. The project provides hardware designs without any built-in security measures against malicious modifications.
  - Missing mitigations:
    - Design review process: Implement a thorough review process for all hardware designs to identify and prevent potentially harmful configurations.
    - Security guidelines: Provide clear security guidelines for users, emphasizing the risks of using hardware designs from untrusted sources.
    - Warnings: Include prominent warnings in the project documentation and README files about the potential risks of hardware damage if designs are maliciously altered.
  - Preconditions:
    - An attacker gains access to the project's design files.
    - The attacker maliciously modifies the `cpu_socket_expansion` design files.
    - A user, unaware of the malicious modification, downloads the modified design files.
    - The user builds the `cpu_socket_expansion` board based on the malicious design.
    - The user plugs the built board into the CPU socket of their retro computer and powers it on.
  - Source code analysis:
    - Vulnerability is in hardware design files (schematic and PCB layout), not in software source code files provided.
    - To analyse, review schematic for `cpu_socket_expansion` project (files not provided in PROJECT FILES, but assumed to exist within the project structure).
    - Look for direct connections between 5V input pins and pins on the CPU socket that should be connected to 3.3V or ground.
    - Review PCB layout to ensure no unintended shorts are introduced that could route 5V to incorrect pins on the CPU socket.
  - Security test case:
    1. Attacker: Download the `cpu_socket_expansion` design files.
    2. Attacker: Modify the schematic to connect a 5V pin from the retro computer's CPU socket (e.g., pin 28 or pin 1) directly to a pin on the expansion board's CPU socket that is intended for a 3.3V signal (e.g., address or data pin expecting 3.3V levels).
    3. Attacker: Generate the PCB layout and gerber files from the modified schematic.
    4. Attacker: Upload the modified design files publicly (e.g., to a forked repository or a file sharing platform).
    5. User: Download the modified design files, believing them to be legitimate.
    6. User: Fabricates the PCB based on the downloaded gerber files and assembles the `cpu_socket_expansion` board.
    7. User: Plugs the assembled `cpu_socket_expansion` board into the CPU socket of a compatible retro computer (Acorn Electron or BBC Micro).
    8. User: Powers on the retro computer.
    9. Expected result: The retro computer fails to boot, exhibits erratic behavior, or the CPU chip is visibly damaged (overheating, smoke, etc.) due to overvoltage.

- Vulnerability Name: Power Distribution Overvoltage
  - Description: An attacker could maliciously alter the `bbc_power_distribution` hardware design to cause the voltage regulator to output an incorrect and damaging voltage, such as +12V instead of +5V or generate a reversed -5V supply. If a user builds this compromised board, it could deliver excessive voltage to the retro computer's motherboard, leading to component failure. This can be achieved by modifying the voltage regulator circuit in the schematic or PCB layout to change the voltage feedback resistors or the regulator IC itself to a higher voltage variant.
  - Impact: High risk of hardware damage to the retro computer's motherboard and components. Overvoltage can destroy sensitive ICs, capacitors, and other circuitry.
  - Vulnerability Rank: High
  - Currently implemented mitigations: None. The project lacks any safeguards against intentional voltage misconfiguration.
  - Missing mitigations:
    - Design verification: Implement design verification steps to ensure the power distribution circuit correctly outputs the intended voltages.
    - Component selection review: Review and lock down the specific voltage regulator components to prevent easy substitution with higher voltage variants.
    - Warnings: Display prominent warnings about the risks associated with modifying and building power distribution circuits, especially from untrusted sources.
  - Preconditions:
    - Attacker gains access to `bbc_power_distribution` design files.
    - Attacker modifies the voltage regulation circuitry in the design to output a damaging voltage.
    - User downloads the modified design files.
    - User builds the `bbc_power_distribution` board based on the malicious design.
    - User connects the board to a power supply and their retro computer motherboard.
  - Source code analysis:
    - Vulnerability resides in the hardware design files, specifically the `bbc_power_distribution` schematic and PCB layout (files not provided in PROJECT FILES).
    - Analyse the voltage regulator circuit in the schematic.
    - Check for modifications that alter the voltage feedback network or replace the regulator IC with a different type that outputs a higher voltage.
    - Examine the PCB layout to ensure no unintended shorts or incorrect component placements that could lead to overvoltage.
  - Security test case:
    1. Attacker: Download the `bbc_power_distribution` design files.
    2. Attacker: Modify the schematic to change the voltage feedback resistors in the LTC1983 -5V generator circuit to output +12V instead of -5V or modify the 5V regulator feedback network.
    3. Attacker: Generate PCB layout and gerber files.
    4. Attacker: Upload the modified design files.
    5. User: Download the modified design files.
    6. User: Builds the modified `bbc_power_distribution` board.
    7. User: Connects the modified board to a 5V power supply and a BBC Model B or Master motherboard.
    8. User: Powers on the system.
    9. Expected result: The retro computer components are damaged due to incorrect power supply voltages. Smoke, overheating, or complete system failure may occur.

- Vulnerability Name: Cartridge/Expansion Board Short Circuit
  - Description: An attacker could intentionally introduce a short circuit in the design of any cartridge or expansion board (e.g., `32kb_flash_cartridge`, `minus_one`, `expansion_minispartan_breakout`). This short circuit, typically between power and ground pins on the cartridge or expansion connector, would directly short circuit the retro computer's power supply when the board is plugged in. Building and using such a maliciously designed board could lead to damage to the computer's power supply and potentially other components due to excessive current flow. This can be achieved by manipulating the PCB layout files to create unintended copper traces connecting power and ground pins on the edge connector footprint.
  - Impact: High risk of hardware damage, primarily to the retro computer's power supply unit (PSU). A severe short circuit could also damage motherboard components or traces due to excessive current.
  - Vulnerability Rank: High
  - Currently implemented mitigations: None. The project lacks any mechanisms to prevent short circuits in user-built boards from modified designs.
  - Missing mitigations:
    - Design rule checks (DRC): Implement and enforce stricter DRC during design to flag potential short circuits, although malicious shorts might be intentionally designed to pass basic DRC.
    - User education: Educate users about the risks of short circuits and the importance of careful PCB assembly and inspection.
    - Warnings: Include explicit warnings in project documentation and build instructions about the dangers of short circuits and the need to verify gerber files and assembled boards against the original design before use.
  - Preconditions:
    - Attacker gains access to cartridge or expansion board design files.
    - Attacker modifies PCB layout to create a short circuit between power and ground pins on the connector.
    - User downloads the malicious design files.
    - User builds the cartridge or expansion board based on the modified design.
    - User plugs the board into their retro computer.
  - Source code analysis:
    - Vulnerability is in hardware PCB layout files for various cartridge/expansion board projects (e.g., `32kb_flash_cartridge`, `minus_one`, `expansion_minispartan_breakout`).
    - Analyse PCB layout files using a PCB design software.
    - Inspect the copper traces around the cartridge or expansion connector footprint for unintended direct connections between power (5V or 3.3V) and GND pins.
    - Verify that design rule checks are enabled and configured to detect short circuits, but note that intentional malicious shorts may be designed to bypass standard DRC.
  - Security test case:
    1. Attacker: Download the design files for `32kb_flash_cartridge`.
    2. Attacker: Open the PCB layout file and draw a copper trace directly connecting the 5V pin to a GND pin on the cartridge edge connector footprint.
    3. Attacker: Generate gerber files for the modified design.
    4. Attacker: Upload the modified design files.
    5. User: Download the modified design files.
    6. User: Fabricates the PCB and assembles the `32kb_flash_cartridge` board.
    7. User: Plugs the modified cartridge into a retro Acorn Electron cartridge slot or Plus 1 expansion.
    8. User: Powers on the retro computer.
    9. Expected result: The retro computer's power supply trips immediately upon power-on, or the power supply or components on the motherboard are damaged due to the short circuit.