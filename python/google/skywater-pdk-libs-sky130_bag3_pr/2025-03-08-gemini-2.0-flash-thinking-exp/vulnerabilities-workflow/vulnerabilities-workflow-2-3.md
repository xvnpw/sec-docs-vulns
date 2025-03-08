## Vulnerability List

### 1. Backdoor Injection in Primitive Definitions

* Description:
    1. An attacker gains write access to the repository (e.g., through compromised credentials or by malicious pull request merge).
    2. The attacker modifies the source code of primitive components in `/code/src/BAG_prim/schematic/`. For instance, they could subtly alter the parameters of transistors (like `nmos4_standard.py`, `pmos4_standard.py`) or resistors (`res_standard.py`, `res_metal_1.py`). These modifications could be designed to be difficult to detect during normal design reviews.
    3. A circuit designer, unaware of the malicious changes, uses these compromised primitives in their analog IC designs using the BAG framework.
    4. The BAG framework generates layouts and netlists based on these modified primitive definitions.
    5. The designer proceeds with simulation, verification, and fabrication of the IC.
    6. The fabricated IC, built using the compromised primitives, exhibits unexpected or malicious behavior due to the injected backdoor. This could range from subtle performance degradation to complete functional failure or introduction of security vulnerabilities in the designed circuit.

* Impact:
    - **Compromised Integrated Circuits**: Circuits designed using backdoored primitives will be inherently flawed. The fabricated ICs may malfunction, have reduced performance, or exhibit unexpected behavior.
    - **Supply Chain Risk**: If the compromised library is widely used, many analog IC designs could be affected, introducing vulnerabilities into the broader supply chain.
    - **Reputational Damage**: The credibility of the library and the organizations relying on it would be severely damaged.
    - **Economic Loss**: Redesign and refabrication of ICs due to discovered backdoors would result in significant financial losses. In severe cases, faulty ICs in critical systems could lead to larger economic or safety impacts.

* Vulnerability Rank: Critical

* Currently Implemented Mitigations:
    - **License**: The project uses a dual-licensing approach (Apache 2.0 or BSD-3-Clause). While licensing is important for usage terms, it does not directly mitigate backdoor injection.
    - **Repository Hosting**: The repository is hosted on GitHub. GitHub provides some basic security features like access control and activity logging, but these are not sufficient to prevent insider threats or sophisticated attacks.

* Missing Mitigations:
    - **Code Review Process**: Implement a rigorous code review process for all changes to the primitive definitions. This should involve multiple independent reviewers with security expertise, specifically looking for subtle malicious modifications.
    - **Access Control**: Enforce strict access control to the repository. Limit write access to only authorized personnel and use multi-factor authentication. Regularly audit access logs.
    - **Integrity Checks**: Implement mechanisms to verify the integrity of the primitive definitions. This could involve:
        - **Digital Signatures**: Digitally sign each primitive definition file. Designers using the library can then verify these signatures to ensure the primitives haven't been tampered with.
        - **Checksums/Hashes**: Generate and publish checksums or cryptographic hashes of the primitive files. Users can verify these hashes against their local copies before using the library.
    - **Security Audits**: Conduct regular security audits of the codebase, focusing on the primitive definitions and the overall build and release process.
    - **Dependency Management**: Implement strict control over dependencies (like BAG framework and SkyWater PDK submodules). Verify the integrity of these dependencies to prevent supply chain attacks through dependent components.
    - **Continuous Integration/Continuous Security (CI/CS)**: Integrate automated security checks into the CI/CD pipeline. This could include static analysis tools to detect suspicious code patterns or deviations from expected behavior in primitive definitions.

* Preconditions:
    - **Write Access**: The attacker needs write access to the project's repository. This could be achieved through compromised developer accounts, insider access, or exploitation of vulnerabilities in the repository hosting platform.
    - **Unsuspecting Designers**: Designers must unknowingly use the backdoored library without proper verification or awareness of the compromise.

* Source Code Analysis:
    - The vulnerability lies in the modifiable Python files within `/code/src/BAG_prim/schematic/`.
    - Files like `nmos4_standard.py`, `pmos4_standard.py`, `res_standard.py`, `mim_standard.py`, etc., define the parameters and behavior of primitive components.
    - For example, consider `nmos4_standard.py`:
    ```python
    from bag.design.module import MosModuleBase
    from bag.design.database import ModuleDB
    from bag.util.immutable import Param

    class BAG_prim__nmos4_standard(MosModuleBase):
        """design module for BAG_prim__nmos4_standard."""
        def __init__(self, database: ModuleDB, params: Param, **kwargs: Any) -> None:
            MosModuleBase.__init__(self, '', database, params, **kwargs)
    ```
    - Currently, these files are simple wrappers. However, if these files were to contain logic to alter device parameters based on some hidden condition, or if the base classes (`MosModuleBase`, `ResMetalModule`, etc.) were compromised (though not within the scope of *this* project, but conceptually), backdoors could be introduced.
    - An attacker could modify the `__init__` method or other methods within these classes to subtly alter the generated netlists or layouts. For instance, they could introduce a conditional statement that slightly changes the width or length of a transistor based on a specific input parameter that might go unnoticed during typical usage but could be exploited later.
    - The lack of integrity checks on these Python files makes the system vulnerable to such modifications.

* Security Test Case:
    1. **Setup Malicious Environment**:
        - Clone the repository to a local machine.
        - Modify the file `/code/src/BAG_prim/schematic/nmos4_standard.py`.
        - Introduce a subtle backdoor. For example, add code to slightly increase the threshold voltage of the NMOS transistor if a specific parameter value is used (this is a simplified example; a real backdoor could be much more subtle and application-specific).
        ```python
        from bag.design.module import MosModuleBase
        from bag.design.database import ModuleDB
        from bag.util.immutable import Param
        from typing import Any

        class BAG_prim__nmos4_standard(MosModuleBase):
            """design module for BAG_prim__nmos4_standard."""
            def __init__(self, database: ModuleDB, params: Param, **kwargs: Any) -> None:
                malicious_param = params.get('malicious_flag', False) # Attacker adds this
                modified_params = params.copy()
                if malicious_param: # Attacker adds conditional backdoor
                    modified_params['l'] = float(params.get('l', 150e-9)) * 1.1 # Slightly increase length if 'malicious_flag' is set
                    print("[WARNING] MALICIOUS MODIFICATION ACTIVE!") # Optional: print a hidden warning
                MosModuleBase.__init__(self, '', database, Param(modified_params), **kwargs)
        ```
    2. **Install the Modified Library**:
        - Run the `install.sh` script in the modified repository to set up the environment with the backdoored primitive.
    3. **Create a Test Design**:
        - Use the BAG framework to create a simple analog circuit design that utilizes the `nmos4_standard` primitive. For example, a simple inverter or amplifier.
        - Include a parameter in the design that can trigger the backdoor (e.g., set `malicious_flag=True` in the transistor parameters when instantiating `nmos4_standard`).
    4. **Generate Layout and Netlist**:
        - Use BAG scripts (e.g., `gen_cell.sh`) to generate the layout and netlist for the test design.
    5. **Simulate the Design**:
        - Simulate the generated netlist using Spectre or another compatible simulator (using `sim_cell.sh`).
        - Run simulations with and without triggering the backdoor parameter (`malicious_flag=True` vs `malicious_flag=False`).
    6. **Analyze Simulation Results**:
        - Compare the simulation results for both cases.
        - If the backdoor is successfully injected, you should observe a subtle but measurable difference in the circuit's behavior (e.g., slightly different gain, offset, or threshold voltage) when the `malicious_flag` is set to `True`. This difference should be attributable to the modified transistor parameters introduced by the backdoor.
    7. **Verification**:
        - This test case demonstrates that modifying primitive definitions can introduce subtle changes in circuit behavior, validating the "Backdoor Injection in Primitive Definitions" vulnerability. The impact of the backdoor can be further amplified and made more malicious by a sophisticated attacker in a real-world scenario.