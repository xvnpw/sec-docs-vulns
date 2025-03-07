### Vulnerability List

- Vulnerability Name: Division by Zero in Projection
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
    - Input validation: Implement checks within the `jaxcam.project` function to detect cases where `local_z` might become zero before performing the division. This could involve analyzing the camera parameters and input points to predict potential division by zero scenarios.
    - Division by zero handling: Implement explicit handling of division by zero. Options include:
        - Returning a specific error code or message to signal the invalid projection.
        - Returning a pre-defined sentinel value (e.g., `NaN` or `Inf` with a warning) to indicate an invalid pixel coordinate.
        - Clipping or clamping the `local_z` value to a small non-zero value to avoid division by zero, although this might introduce inaccuracies in the projection.
        - Raising an exception to halt the process and signal an error condition, allowing the calling application to handle the error gracefully.
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
      Imagine a camera at the origin looking along the positive z-axis. If a 3D point is positioned such that after transformation to camera coordinates, its z-coordinate becomes zero (meaning it lies on the camera's focal plane), then projecting this point will involve dividing by zero, leading to numerical instability.
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
        4. **Define a malicious 3D point:** Create a 3D point that will result in `local_z = 0` after transformation. For the given camera, a point `[1.0, 0.0, 5.0]` in world coordinates will achieve this because its vector from camera position `[1.0, 0.0, 0.0]` is orthogonal to the camera's optical axis (z-axis).
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