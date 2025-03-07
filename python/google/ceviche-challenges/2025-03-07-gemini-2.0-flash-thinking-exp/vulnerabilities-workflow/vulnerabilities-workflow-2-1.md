- Vulnerability Name: Insufficient Input Validation in `insert_design_variable` Primitive
- Description:
    - The `insert_design_variable` primitive function in `/code/ceviche_challenges/primitives.py` is used to insert a `design_var` array into a `destination` array at specified `coords`.
    - While the function performs some input validation, it can be bypassed by providing a `design_var` with `NaN` or `Inf` values.
    - If a user provides a `design_variable` containing `NaN` or `Inf` values to the `simulate()` function of a model, these values will be inserted into the permittivity distribution through `insert_design_variable`.
    - The `ceviche` simulator, which is used in the backend, might not handle `NaN` or `Inf` values gracefully, potentially leading to unexpected behavior, numerical instability, or crashes.
    - An attacker could craft a malicious `design_variable` array containing `NaN` or `Inf` values and pass it to the `simulate()` function to trigger this vulnerability.
- Impact:
    - Numerical instability during simulation.
    - Unexpected simulation results, potentially leading to incorrect design optimizations.
    - Program crash due to unhandled `NaN` or `Inf` values in the `ceviche` simulator.
- Vulnerability Rank: Medium
- Currently Implemented Mitigations:
    - Input validation in `insert_design_variable` checks for:
        - `design_var` shape compatibility with `destination` shape.
        - Positive values in `coords`.
        - Correct ordering of coordinates (`x_min < x_max`, `y_min < y_max`).
        - `coords` staying within the bounds of `destination` array.
    - Location: `/code/ceviche_challenges/primitives.py` - `insert_design_variable` function.
- Missing Mitigations:
    - Input validation in `insert_design_variable` should be extended to check for non-finite values (NaN, Inf) in the `design_var` array.
    - Input validation in the `simulate()` function or within model classes could explicitly check the `design_variable` for `NaN` or `Inf` values before passing it to `insert_design_variable` and the ceviche simulator.
- Preconditions:
    - An attacker needs to be able to provide input to the `simulate()` function of any model in the `ceviche_challenges` library. This is the standard use case of the library.
- Source Code Analysis:
    - File: `/code/ceviche_challenges/primitives.py`
    ```python
    @autograd.primitive
    def insert_design_variable(design_var: np.ndarray, destination: np.ndarray,
                            coords: Tuple[int, int, int, int]) -> np.ndarray:
        """Insert 2D design variable a into a larger 2D ndarray at coordinates.
        ...
        """
        (x_min, y_min, x_max, y_max) = coords
        if (design_var.shape[0] > destination.shape[0] or
            design_var.shape[1] > destination.shape[1]):
            raise ValueError(...)
        if not np.all([coord > 0 for coord in coords]):
            raise ValueError(...)
        if x_min >= x_max:
            raise ValueError(...)
        if y_min >= y_max:
            raise ValueError(...)
        if (x_max >= destination.shape[0] or y_max >= destination.shape[1]):
            raise ValueError(...)
        destination_ = np.copy(destination)
        destination_[coords[0]:coords[2], coords[1]:coords[3]] = design_var # Vulnerability: No NaN/Inf check here
        return destination_
    ```
    - The `insert_design_variable` function performs checks on the shape and coordinates, but it does not validate the *values* within the `design_var` array.
    - Specifically, it doesn't check for `NaN` or `Inf` values before inserting `design_var` into `destination`.
    - When `simulate()` is called in any model (e.g., `WaveguideBendModel.simulate()` in `/code/ceviche_challenges/waveguide_bend/model.py`), it uses `model.epsilon_r(design_variable)` which eventually calls `primitives.insert_design_variable` to incorporate the `design_variable` into the permittivity distribution.
    - If `design_variable` contains `NaN` or `Inf`, these non-finite values will be propagated into the `epsilon_r` array used by the `ceviche` simulator.
    - The `ceviche` simulator might not be designed to handle such inputs, leading to issues.
- Security Test Case:
    - Step 1: Import necessary libraries and a model from `ceviche_challenges`.
        ```python
        import numpy as np
        import ceviche_challenges
        ```
    - Step 2: Instantiate a model (e.g., `WaveguideBendModel`).
        ```python
        spec = ceviche_challenges.waveguide_bend.prefabs.waveguide_bend_2umx2um_spec()
        params = ceviche_challenges.waveguide_bend.prefabs.waveguide_bend_sim_params()
        model = ceviche_challenges.waveguide_bend.model.WaveguideBendModel(params, spec)
        ```
    - Step 3: Create a malicious `design_variable` array containing `NaN` values.
        ```python
        design_nan = np.ones(model.design_variable_shape)
        design_nan[0, 0] = np.nan
        ```
    - Step 4: Call the `simulate()` function with the malicious `design_variable`.
        ```python
        try:
            s_params, fields = model.simulate(design_nan)
            print("Simulation completed, but expected potential numerical issues or crash.")
        except Exception as e:
            print(f"Simulation likely crashed or raised an exception due to NaN values: {e}")
        ```
    - Step 5: Analyze the output. If the simulation completes without errors, check for `NaN` or `Inf` values in the `fields` output, which would indicate numerical instability. If the simulation crashes, it confirms the vulnerability.

    **Expected Result of Test Case:** The simulation might complete but produce incorrect results with `NaN` or `Inf` values in the output, or it might crash due to numerical instability in the `ceviche` simulator when processing `NaN` or `Inf` permittivity values. This demonstrates that the lack of input validation for non-finite values in `design_variable` can lead to unexpected and potentially harmful behavior.