## Combined Vulnerability List

### 1. Lack of Input Validation in Camera Parameters

- Description:
    1. The `jaxcam.Camera.create` function in `/code/jaxcam/_src/camera.py` is used to instantiate `Camera` objects.
    2. This function and related update functions accept various parameters such as `focal_length`, `principal_point`, `image_size`, `skew`, `pixel_aspect_ratio`, `radial_distortion`, and `tangential_distortion` to define the camera model.
    3. However, there is insufficient or no validation of these input parameters to ensure they are within valid ranges or of the expected type.
    4. An attacker could provide maliciously crafted or out-of-range values for these parameters during camera creation or update.
    5. For example, an attacker might provide extremely large values for `focal_length`, negative values for `image_size`, or invalid distortion coefficients like NaN or Inf.
    6. When these maliciously crafted camera objects are used in subsequent projection, ray generation, or other camera operations, they can lead to incorrect or unexpected results.
    7. Applications relying on `jaxcam` for accurate camera modeling in security-sensitive contexts could be vulnerable if they use camera objects created or updated with untrusted or unvalidated parameters. This can lead to manipulation of computer vision applications, inaccurate results, and potentially application crashes due to numerical instability.

- Impact:
    - Incorrect 3D projection and camera modeling.
    - Misrepresentation of the camera model.
    - Manipulation of computer vision applications relying on `jaxcam` for accurate camera models.
    - Potential for application crashes or unexpected behavior due to numerical instability or invalid calculations.
    - Inaccurate results in computer vision tasks like object detection, pose estimation, or SLAM, if these tasks rely on jaxcam's camera model.
    - Potential security vulnerabilities in applications that depend on accurate camera models for security tasks, such as AR/VR applications, robotics, or security systems, where incorrect projections could lead to bypassing security measures or misinterpreting the environment.

- Vulnerability Rank: Medium

- Currently Implemented Mitigations:
    - Type conversion to `jnp.float32` for all input parameters in `Camera.create`.
    - Padding of `radial_distortion` to length 4 in `Camera.create`.
    - Basic shape checks in some functions (e.g., `update_intrinsic_matrix`).
    - No explicit validation of the range or semantic correctness of camera parameters is performed.

- Missing Mitigations:
    - Input validation should be added to the `Camera.create` function and any functions that update camera parameters to check for reasonable ranges and valid types for all camera parameters.
    - Specific validations should include:
        - `focal_length`: Must be positive.
        - `image_size`: Must be positive integers.
        - `pixel_aspect_ratio`: Must be positive.
        - `principal_point`: Should be within or close to `image_size` boundaries.
        - `skew`: Should be within a reasonable range (e.g., close to zero for typical cameras).
        - `radial_distortion` and `tangential_distortion`: Should be checked for NaN or Inf values and potentially for extreme magnitudes or unreasonable values based on the camera model.

- Preconditions:
    - An attacker must be able to control or influence the input parameters passed to the `jaxcam.Camera.create` function or camera update functions.
    - This could occur if:
        - Camera parameters are loaded from an external, untrusted source, such as configuration files (e.g., JSON, YAML).
        - Camera parameters are received as input from user-provided data or external APIs.
        - A higher-level application does not properly sanitize user-provided camera settings before using `jaxcam`.
        - The attacker has some form of access to modify camera parameters in memory.

- Source Code Analysis:
    - File: `/code/jaxcam/_src/camera.py`
    - Function: `Camera.create`
    ```python
    @classmethod
    def create(
        cls,
        orientation: Optional[jnp.ndarray] = None,
        position: Optional[jnp.ndarray] = None,
        focal_length: Optional[jnp.ndarray] = None,
        principal_point: Optional[jnp.ndarray] = None,
        image_size: Optional[jnp.ndarray] = None,
        skew: Union[jnp.ndarray, float] = 0.0,
        pixel_aspect_ratio: Union[jnp.ndarray, float] = 1.0,
        radial_distortion: Optional[jnp.ndarray] = None,
        tangential_distortion: Optional[jnp.ndarray] = None,
        invert_distortion: bool = False,
        is_fisheye: bool = False,
    ) -> 'Camera':
        """Creates a camera with reasonable default values."""
        if position is None:
            position = jnp.zeros(3)
        if orientation is None:
            orientation = jnp.eye(3)
        if image_size is None:
            image_size = jnp.ones(2)
        if principal_point is None:
            principal_point = image_size / 2.0
        if focal_length is None:
            # Default focal length produces a FoV of 2*atan(0.5) ~= 53 degrees.
            focal_length = image_size[..., 0]

        # Ensure all items are strongly typed arrays to avoid triggering a cache
        # miss during JIT compilation due to weak type semantics.
        # See: https://jax.readthedocs.io/en/latest/type_promotion.html
        asarray = functools.partial(jnp.asarray, dtype=jnp.float32)

        kwargs = {
            'orientation': asarray(orientation),
            'position': asarray(position),
            'focal_length': asarray(focal_length),
            'principal_point': asarray(principal_point),
            'image_size': asarray(image_size),
            'skew': asarray(skew),
            'pixel_aspect_ratio': asarray(pixel_aspect_ratio),
        }

        if radial_distortion is not None:
            # Insert the 4th radial distortion coefficient if not present.
            radial_distortion = jnp.pad(
                asarray(radial_distortion),
                pad_width=(0, 4 - radial_distortion.shape[-1]),
            )
            kwargs['radial_distortion'] = asarray(radial_distortion)

        if tangential_distortion is not None:
            kwargs['tangential_distortion'] = asarray(tangential_distortion)

        if invert_distortion and (
            radial_distortion is not None or tangential_distortion is not None
        ):
            kwargs['use_inverted_distortion'] = True

        if is_fisheye:
            kwargs['projection_type'] = ProjectionType.FISHEYE
        else:
            kwargs['projection_type'] = ProjectionType.PERSPECTIVE

        return cls(**kwargs)
    ```
    - The `Camera.create` method in `/code/jaxcam/_src/camera.py` lacks input validation for parameters like `focal_length`, `principal_point`, `image_size`, `skew`, and distortion coefficients.
    - The code primarily focuses on setting default values, converting inputs to `jnp.float32` arrays, and padding `radial_distortion`.
    - There are no checks to ensure that `focal_length`, `image_size`, and `pixel_aspect_ratio` are positive, `principal_point` is within image bounds, or that distortion coefficients are valid numerical values within reasonable ranges.
    - This absence of input validation allows for the creation of `Camera` objects with semantically invalid parameters, which can lead to incorrect behavior in functions that use these camera objects, such as `project`, `pixels_to_rays`, etc.

- Security Test Case:
    1. **Direct Camera Creation Test:**
        - Import the `jaxcam` library.
        - Create a `Camera` object with an extremely large focal length, e.g., `focal_length=jnp.array([1e10])`.
        - Define a set of 3D points, e.g., `points = jnp.array([[1.0, 2.0, 3.0], [4.0, 5.0, 6.0]])`.
        - Project these points using the created camera: `pixels = jaxcam.project(camera, points)`.
        - Print the resulting `pixels`.
        - Compare these pixel coordinates to the expected pixel coordinates if a valid `focal_length` (e.g., `512`) were used. The pixel coordinates should be drastically different, demonstrating the impact of the malicious `focal_length`.
        - Repeat steps with other malicious parameters such as negative `image_size` or extreme `radial_distortion` coefficients and observe the output of projection and other camera operations.

    2. **JSON Configuration Loading Test:**
        - Setup: Prepare an application that uses `jaxcam` to load camera parameters from a JSON file using `jaxcam.io.from_nerfies_json_file` and then projects 3D points.
        - Craft Malicious Input: Create a JSON file named `malicious_camera.json` with a negative `focal_length`:
            ```json
            {
              "orientation": [[1.0, 0.0, 0.0], [0.0, 1.0, 0.0], [0.0, 0.0, 1.0]],
              "position": [0.0, 0.0, 0.0],
              "focal_length": -100.0,
              "principal_point": [256.0, 256.0],
              "image_size": [512, 512],
              "skew": 0.0,
              "pixel_aspect_ratio": 1.0
            }
            ```
        - Run Application: Execute the application, instructing it to load camera parameters from `malicious_camera.json`.
        - Observe Behavior: Observe the output of the projection. Due to the negative `focal_length`, projected pixel coordinates will be inverted and incorrect.
        - Verification: Verify that the projected pixel coordinates are incorrect and demonstrate that invalid camera parameters can be used to create a `jaxcam.Camera` object without any validation error, leading to unexpected or incorrect behavior in applications using this library.

### 2. Division by Zero in Projection

- Description:
    1. An attacker provides a set of 3D world points and a camera configuration to the `jaxcam.project` function.
    2. The `jaxcam.project` function internally calls `world_points_to_local_points` to transform world points into camera local coordinates.
    3. Due to specific combinations of camera orientation, position, and input 3D points, the z-component of the transformed local points (`local_z`) can become zero.
    4. In the subsequent steps of `jaxcam.project`, the code performs divisions by `local_z` to normalize the x and y coordinates (`x = local_x / local_z`, `y = local_y / local_z`).
    5. When `local_z` is zero, these divisions result in a division by zero error, producing `NaN` (Not a Number) or `Inf` (Infinity) values in the output pixel coordinates.

- Impact:
    - Numerical instability. The `jaxcam.project` function may return `NaN` or `Inf` values instead of valid pixel coordinates when provided with specific inputs.
    - Applications relying on `jaxcam` for camera projection may produce incorrect or unreliable outputs when encountering such numerical issues. This can lead to failures in computer vision tasks that depend on accurate projection, such as object detection, pose estimation, or rendering.

- Vulnerability Rank: Medium

- Currently Implemented Mitigations:
    - None. There is no input validation or error handling in the `jaxcam.project` function to prevent or manage division by zero errors.

- Missing Mitigations:
    - Division by zero handling: Implement explicit handling of division by zero within the `jaxcam.project` function. Options include:
        - Returning a specific error code or message to signal the invalid projection.
        - Returning a pre-defined sentinel value (e.g., `NaN` or `Inf` with a warning) to indicate an invalid pixel coordinate.
        - Raising an exception to halt the process and signal an error condition, allowing the calling application to handle the error gracefully.
    - Input validation: While directly preventing all division by zero scenarios through input validation might be complex, consider adding checks for extreme camera parameters or point configurations that are more likely to lead to such issues, and provide warnings or errors.

- Preconditions:
    - The attacker needs to craft specific 3D world points and potentially camera parameters that, when processed by `jaxcam.project`, will result in the z-component of the transformed local points being equal to zero.
    - The attacker requires the ability to provide input to an application that utilizes the `jaxcam.project` function. This could be through an API, configuration file, or direct interaction with the application if it exposes camera projection functionality.

- Source Code Analysis:
    - File: `/code/jaxcam/_src/camera.py`
    - Function: `project(camera: Camera, points: jnp.ndarray)`
    - Step-by-step analysis:
        1. `local_points = world_points_to_local_points(camera, points)`: World points are transformed to camera local coordinates.
        2. `local_z = local_points[..., 2]`: Extracts the z-component of the local points.
        3. `x = local_x / local_z`: Divides the x-component by the z-component.
        4. `y = local_y / local_z`: Divides the y-component by the z-component.
    - Vulnerable code snippet:
      ```python
      x = local_x / local_z
      y = local_y / local_z
      ```
    - Visualization:
      Imagine a camera. If a 3D point is positioned such that after transforming it to the camera's local coordinate system, its z-coordinate becomes zero (meaning it lies on the camera's focal plane), then projecting this point involves dividing by zero, leading to numerical instability.

- Security Test Case:
    - Step-by-step test:
        1. **Setup:** Create a Python test script.
        2. **Import libraries:**
           ```python
           import jax
           import jax.numpy as jnp
           import jaxcam
           ```
        3. **Create a Camera object:** Instantiate a `jaxcam.Camera` with specific parameters to easily trigger the vulnerability.
           ```python
           camera = jaxcam.Camera.create(
               orientation=jnp.eye(3), # Identity orientation
               position=jnp.array([0.0, 0.0, 5.0]), # Camera position at (0, 0, 5)
               image_size=jnp.array([512, 512]),
               focal_length=jnp.array(512)
           )
           ```
        4. **Define a malicious 3D point:** Create a 3D point that will result in `local_z = 0` after transformation. For the given camera, a point `[1.0, 0.0, 5.0]` in world coordinates will achieve this.
           ```python
           point = jnp.array([[1.0, 0.0, 5.0]])
           ```
        5. **Call `jaxcam.project`:** Execute the vulnerable function with the crafted camera and point.
           ```python
           pixels = jaxcam.project(camera, point)
           ```
        6. **Assert vulnerability:** Check if the output `pixels` contains `NaN` or `Inf`, indicating a division by zero error.
           ```python
           assert jnp.isnan(pixels).any() or jnp.isinf(pixels).any()
           print("Vulnerability Found: Division by zero occurred, output is:", pixels)
           ```
        7. **Run the test:** Execute the Python script. If the assertion passes and the message "Vulnerability Found: Division by zero occurred..." is printed, the vulnerability is confirmed.