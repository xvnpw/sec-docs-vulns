- vulnerability name: Malicious Modification of Primitive Component Parameters

- description: |
    An attacker with write access to the repository can modify the Python files defining primitive components in the `/code/src/BAG_prim/schematic/` directory. These files define the electrical characteristics of basic circuit elements like transistors, resistors, and capacitors used by the BAG3 framework. By altering parameters within these files, an attacker can subtly change the behavior of these primitives. For example, they could modify the `MosModuleBase` class in files like `nmos4_standard.py` to alter transistor strength (e.g., by changing width or length parameters), or modify `ResPhysicalModuleBase` in `res_standard.py` to change resistor values. When users generate analog circuits using these compromised primitives, the resulting circuits will exhibit unexpected behavior due to the altered component characteristics. This can lead to functional failures or create security vulnerabilities in chips designed with these libraries.

    Steps to trigger vulnerability:
    1. An attacker gains write access to the repository, either by compromising developer accounts or exploiting repository access control vulnerabilities (outside the scope of these project files).
    2. The attacker navigates to the `/code/src/BAG_prim/schematic/` directory.
    3. The attacker opens and modifies a primitive definition file, such as `nmos4_standard.py`, `res_standard.py`, or `mim_standard.py`.
    4. The attacker alters parameters within the Python class definition to subtly change the electrical characteristics of the component. For example, in `nmos4_standard.py`, they might modify the `MosModuleBase.__init__` method to change default transistor width or length, or add code that dynamically alters these parameters based on certain conditions.
    5. The attacker commits and pushes these malicious changes to the repository.
    6. Unsuspecting users then clone or pull the compromised repository to use the BAG3 primitives library in their analog circuit designs.
    7. When these users generate circuits using the BAG3 framework, the modified primitive components are used, resulting in circuits with altered and potentially vulnerable behavior.

- impact: |
    The impact of this vulnerability is high. Compromised primitive components can introduce subtle hardware vulnerabilities into analog integrated circuits designed using the BAG3 framework and SkyWater 130nm process. This can lead to:
    - Functional failures: Circuits may not operate as intended, leading to system malfunctions.
    - Performance degradation: Circuits may exhibit reduced performance, such as lower speed or higher power consumption.
    - Security vulnerabilities: In analog circuits, subtle changes in component characteristics can be exploited to create backdoors or bypass security mechanisms. For example, an attacker might weaken a transistor in a critical path, making it susceptible to noise or signal manipulation, or alter resistor values in a sensing circuit to skew measurements.
    - Supply chain attack: This vulnerability represents a supply chain attack, as users unknowingly incorporate compromised components into their designs, inheriting the injected vulnerabilities. The impact can be widespread, affecting all users of the compromised library.

- vulnerability rank: High

- currently implemented mitigations:
    - None. The repository relies on the security of the development and distribution process. There are no implemented mechanisms within the project files to detect or prevent malicious modifications of primitive components.

- missing mitigations:
    - Code signing: Implement code signing for the primitive component files. This would allow users to verify the integrity and authenticity of the components before use.
    - Integrity checks: Implement checksums or hash verification for primitive component files. Users could then compare these checksums against known good values to detect modifications.
    - Repository access control and monitoring: While not directly in the project files, strong repository access control and monitoring are essential to prevent unauthorized modifications. Regular security audits of the repository and development infrastructure are needed.
    - Security review of primitive definitions: Implement a rigorous security review process for all primitive component definitions, especially when changes are made. This review should focus on identifying any unintended or malicious changes that could introduce vulnerabilities.

- preconditions:
    1. The attacker must have write access to the repository.
    2. Users must be using the BAG3 framework and this primitives library to generate analog circuits.
    3. Users must clone or pull the compromised repository after the attacker has injected malicious modifications.

- source code analysis: |
    The vulnerability lies in the lack of integrity protection for the primitive component definition files located in `/code/src/BAG_prim/schematic/`.

    Let's take `nmos4_standard.py` as an example:

    ```python
    File: /code/src/BAG_prim/schematic/nmos4_standard.py
    Content:
    ...
    from bag.design.module import MosModuleBase
    from bag.design.database import ModuleDB
    from bag.util.immutable import Param

    # noinspection PyPep8Naming
    class BAG_prim__nmos4_standard(MosModuleBase):
        """design module for BAG_prim__nmos4_standard.
        """

        def __init__(self, database: ModuleDB, params: Param, **kwargs: Any) -> None:
            MosModuleBase.__init__(self, '', database, params, **kwargs)
    ```

    This file, and others like it, defines a Python class (`BAG_prim__nmos4_standard`) that inherits from `MosModuleBase`.  The `__init__` method is where parameters for the MOSFET component would be set, although in this basic example, it's directly calling the parent class's initializer.

    **Attack Scenario & Source Code Modification:**

    An attacker could modify `nmos4_standard.py` to inject malicious behavior. For instance, they could alter the transistor width (`w`) parameter, making it smaller than intended, thus weakening the transistor.

    **Example of malicious modification in `nmos4_standard.py`:**

    ```python
    File: /code/src/BAG_prim/schematic/nmos4_standard.py (Modified by attacker)
    Content:
    ...
    from bag.design.module import MosModuleBase
    from bag.design.database import ModuleDB
    from bag.util.immutable import Param

    # noinspection PyPep8Naming
    class BAG_prim__nmos4_standard(MosModuleBase):
        """design module for BAG_prim__nmos4_standard.
        """

        def __init__(self, database: ModuleDB, params: Param, **kwargs: Any) -> None:
            modified_params = dict(params) # Create a mutable copy
            if 'w' in modified_params:
                modified_params['w'] = modified_params['w'] * 0.8 # Reduce width by 20% maliciously
            MosModuleBase.__init__(self, '', database, Param(modified_params), **kwargs) # Pass modified params
    ```

    In this modified code, the attacker has intercepted the `params` dictionary passed to the `__init__` method. They then check if a 'w' (width) parameter exists and, if so, reduce its value by 20%.  This change is subtle and might not be immediately obvious during a casual code review.

    When a user instantiates a `BAG_prim__nmos4_standard` component with a specified width, the actual transistor created will be 20% narrower than intended. This can lead to various circuit malfunctions depending on how this transistor is used in the design.

    Similar modifications can be made to other primitive component files to alter resistor values, capacitor sizes, or other electrical characteristics. The lack of any integrity checks allows these malicious changes to be propagated to users without detection.

- security test case: |
    This test case demonstrates how a malicious modification in `nmos4_standard.py` can alter the behavior of a generated circuit.

    Preconditions for test case:
    1.  Set up a BAG3 development environment with the SkyWater 130nm primitives library according to the project's documentation.
    2.  Have access to Virtuoso or a compatible EDA tool for schematic and simulation.

    Steps for test case:
    1. **Baseline Test (Unmodified Primitives):**
        a. Generate a simple test circuit using the BAG3 framework that includes an `nmos4_standard` transistor. For example, a simple inverter or amplifier.
        b. Simulate the test circuit using Spectre or a compatible simulator across nominal process, voltage, and temperature (PVT) conditions.
        c. Record the key performance metrics of the circuit, such as gain, bandwidth, or switching threshold. This will serve as the baseline.

    2. **Malicious Modification:**
        a. Navigate to the `/code/src/BAG_prim/schematic/` directory in your local repository clone.
        b. Open the `nmos4_standard.py` file in a text editor.
        c. Insert the malicious code snippet from the Source Code Analysis section into the `__init__` method of the `BAG_prim__nmos4_standard` class. Save the modified file.

    3. **Test with Modified Primitives:**
        a. Regenerate the same test circuit from step 1a using the BAG3 framework with the *modified* `nmos4_standard.py` file in place. Ensure that the BAG framework picks up the changes (you might need to re-initialize or clear caches depending on the framework's behavior).
        b. Simulate the *regenerated* test circuit using the same simulator and PVT conditions as in step 1b.
        c. Record the key performance metrics of the circuit, using the modified primitives.

    4. **Verification:**
        a. Compare the performance metrics recorded in step 3c (modified primitives) with the baseline metrics from step 1c (unmodified primitives).
        b. Observe if there is a significant and *predictable* deviation in performance due to the malicious modification. For example, if the transistor width was reduced, you should see a reduction in drive strength, potentially affecting gain or speed of the circuit.
        c. If the performance metrics are measurably and predictably altered in a way consistent with the injected malicious modification (e.g., a reduction in gain if transistor width was reduced), then the vulnerability is validated.

    Expected result: The security test case should demonstrate that modifying the `nmos4_standard.py` file leads to a measurable change in the behavior of circuits generated using this primitive. This proves that an attacker can successfully inject vulnerabilities by modifying these primitive definition files.