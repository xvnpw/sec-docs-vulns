- Vulnerability Name: Insufficient Input Validation in Camera Parameters
- Description:
  1. An attacker provides maliciously crafted camera parameters when creating or updating a `jaxcam.Camera` object.
  2. The `jaxcam` library does not sufficiently validate these parameters, such as `focal_length`, `principal_point`, `skew`, `pixel_aspect_ratio`, `radial_distortion`, and `tangential_distortion`, to ensure they are within valid ranges or of the expected type.
  3. These invalid parameters are used in subsequent camera operations like projection, ray generation, or transformations.
  4. Due to the lack of validation, the camera operations may produce incorrect or unexpected results, potentially leading to application-level vulnerabilities in systems using `jaxcam` for computer vision tasks.
- Impact:
  - Incorrect 3D projection and camera modeling.
  - Manipulation of computer vision applications relying on `jaxcam` for accurate camera models.
  - Potential for application crashes or unexpected behavior due to numerical instability or invalid calculations.
  - Inaccurate results in computer vision tasks like object detection, pose estimation, or SLAM, if these tasks rely on jaxcam's camera model.
- Vulnerability Rank: Medium
- Currently Implemented Mitigations:
  - Type conversion to `jnp.float32` in `Camera.create`.
  - Padding of `radial_distortion` to length 4 in `Camera.create`.
  - Basic shape checks in some functions (e.g., `update_intrinsic_matrix`).
- Missing Mitigations:
  - Validation of the range and type of camera parameters in `Camera.create` and update functions:
    - `focal_length`: Must be positive.
    - `principal_point`: Should be within or close to `image_size` boundaries.
    - `skew`: Should be within a reasonable range (e.g., close to zero for typical cameras).
    - `pixel_aspect_ratio`: Must be positive.
    - `radial_distortion` and `tangential_distortion`: Should be checked for NaN or Inf values and potentially for extreme magnitudes.
    - `image_size`: Must be positive integers.
- Preconditions:
  - An attacker must be able to provide or influence the camera parameters used to create or update a `jaxcam.Camera` object. This could be through:
    - Loading camera parameters from an external configuration file controlled by the attacker.
    - Providing camera parameters as input to a function that uses `jaxcam`.
    - Modifying camera parameters in memory if the attacker has some form of access to the application.
- Source Code Analysis:
  - In `/code/jaxcam/_src/camera.py`, the `Camera.create` method is used to instantiate camera objects.
  - Reviewing the source code of `Camera.create` in `/code/jaxcam/_src/camera.py`:
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
      # ... (rest of the create method)
    ```
  - The code lacks explicit validation checks for the input parameters such as `focal_length`, `principal_point`, `image_size`, `skew`, `pixel_aspect_ratio`, `radial_distortion`, and `tangential_distortion`.
  - The method focuses on setting default values, converting inputs to `jnp.float32` arrays, and padding `radial_distortion`.
  - There are no checks to ensure that `focal_length` is positive, `principal_point` is within image bounds, `pixel_aspect_ratio` is positive, or that distortion coefficients are valid numbers.
  - This absence of input validation allows for the creation of `Camera` objects with semantically invalid parameters, which can lead to incorrect behavior in functions that use these camera objects, such as `project`, `pixels_to_rays`, etc.
- Security Test Case:
  1. Setup: Prepare an application that uses `jaxcam` to load camera parameters from a JSON file using `jaxcam.io.from_nerfies_json_file` and then projects 3D points.
  2. Craft Malicious Input: Create a JSON file named `malicious_camera.json` with a negative `focal_length`:
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
  3. Run Application: Execute the application, instructing it to load camera parameters from `malicious_camera.json`.
  4. Observe Behavior: Observe the output of the projection. Due to the negative `focal_length`, projected pixel coordinates will be inverted and incorrect. The application might not crash, but the results will be semantically wrong for computer vision tasks. For example, projecting points that should be within the image frame might result in coordinates outside the frame or in mirrored positions.
  5. Verification: Verify that the projected pixel coordinates are incorrect and demonstrate that invalid camera parameters can be used to create a `jaxcam.Camera` object without any validation error, leading to unexpected or incorrect behavior in applications using this library.