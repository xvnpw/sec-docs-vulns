## Vulnerability List

### 1. Buffer Overflow in Tile Key Generation

- **Description:**
    1. An attacker crafts a malicious 3D scene or Gaussian dataset where at least one Gaussian is designed to cover an exceptionally large number of tiles when projected onto the image plane. This can be achieved by manipulating the Gaussian's scale and position.
    2. During the vertex shader stage (`vertex_shader.slang`), the number of tiles touched by this malicious Gaussian is calculated and stored in `tiles_touched` for this Gaussian. Due to the crafted Gaussian properties, this value becomes excessively large.
    3. In the tile shader stage (`tile_shader_slang.py`), the `total_size_index_buffer` is computed by summing up the `tiles_touched` values for all Gaussians using `torch.cumsum`. This `total_size_index_buffer` determines the allocation size for `unsorted_keys` and `unsorted_gauss_idx` tensors.
    4. The `generate_keys` kernel in `tile_shader.slang` is then launched. For each Gaussian, this kernel iterates up to `tiles_touched[gaussian_idx]` times, writing tile keys and Gaussian indices into `out_unsorted_keys` and `out_unsorted_gauss_idx` at indices calculated using `index_buffer_offset`.
    5. Due to the maliciously inflated `tiles_touched` value from the crafted Gaussian, the loop in `generate_keys` attempts to write far beyond the allocated bounds of `out_unsorted_keys` and `out_unsorted_gauss_idx`, causing a buffer overflow.

- **Impact:** Memory corruption, potentially leading to arbitrary code execution. An attacker could potentially overwrite critical data or inject malicious code into memory by controlling the content written during the buffer overflow.

- **Vulnerability Rank:** Critical

- **Currently Implemented Mitigations:** None. There are no input validations or bounds checks in place to prevent a Gaussian from touching an excessive number of tiles or to prevent buffer overflows in the key generation process.

- **Missing Mitigations:**
    - **Input Validation:** Implement validation checks on the input Gaussian dataset to limit the maximum size and screen-space projection area of Gaussians. This could involve setting maximum scale limits or validating the projected bounding box size to prevent excessively large tile coverage.
    - **Tile Count Limiting:** Enforce a maximum limit on the number of tiles a single Gaussian can interact with. If a Gaussian exceeds this limit, it could be clamped or discarded.
    - **Bounds Checking in Shader:** Introduce explicit bounds checking within the `generate_keys` shader to ensure that writes to `out_unsorted_keys` and `out_unsorted_gauss_idx` are always within the allocated buffer boundaries.
    - **Safer Integer Types:** Use larger integer types (e.g., `int64_t` in Slang and `torch.int64` in Python) for `tiles_touched` and related size calculations to reduce the risk of integer overflows, although the primary issue is buffer overflow, not integer overflow itself causing incorrect size calculation.

- **Preconditions:**
    - The attacker must be able to provide a maliciously crafted 3D scene or Gaussian splat dataset as input to the Slang.D rasterizer. This is the primary attack vector as described in the project description.

- **Source Code Analysis:**
    - **`slang_gaussian_rasterization/internal/tile_shader_slang.py`:**
        - Line 87: `index_buffer_offset = torch.cumsum(tiles_touched, dim=0, dtype=tiles_touched.dtype)` calculates cumulative sum of `tiles_touched`.
        - Line 88: `total_size_index_buffer = index_buffer_offset[-1]` gets the total size from the last element of `index_buffer_offset`.
        - Line 89 & 92: `unsorted_keys` and `unsorted_gauss_idx` tensors are allocated with `total_size_index_buffer`.
    - **`slang_gaussian_rasterization/internal/slang/tile_shader.slang` - `generate_keys` kernel:**
        ```slang
        kernel void generate_keys(
            // ... inputs ...
            WBuffer<uint64_t> out_unsorted_keys,
            WBuffer<int> out_unsorted_gauss_idx,
            uint32_t grid_height,
            uint32_t grid_width)
        {
            uint32_t gaussian_idx = dispatchThreadID().x;
            int32_t tile_count = tiles_touched[gaussian_idx];
            int32_t offset = index_buffer_offset[gaussian_idx];

            for(int tile_id_idx = 0; tile_id_idx < tile_count; ++tile_id_idx)
            {
                int2 tile_pos_rect = rect_tile_space[gaussian_idx][tile_id_idx];
                uint32_t tile_id_linear = tile_pos_rect.y * grid_width + tile_pos_rect.x;
                uint64_t key = ((uint64_t)tile_id_linear << 32) | (0xFFFFFFFF - gaussian_idx);

                int write_idx = offset + tile_id_idx; // Potential out-of-bounds write
                out_unsorted_keys[write_idx] = key;
                out_unsorted_gauss_idx[write_idx] = gaussian_idx;
            }
        }
        ```
        - The loop condition `tile_id_idx < tile_count` uses `tiles_touched[gaussian_idx]` to control the number of iterations.
        - `write_idx = offset + tile_id_idx` calculates the write index. If `tile_count` (derived from attacker-controlled Gaussian data) is excessively large, `write_idx` can exceed the allocated buffer size, leading to a buffer overflow when writing to `out_unsorted_keys[write_idx]` and `out_unsorted_gauss_idx[write_idx]`.

- **Security Test Case:**
    1. **Prepare Malicious Input:** Create a Python script to generate a Gaussian dataset. In this dataset, include at least one Gaussian with extremely large scales (e.g., scales = `torch.tensor([1e5, 1e5, 1e5])`) and position it such that its projection covers a significant portion of the image, thus touching a large number of tiles.
    2. **Integrate with Rasterizer:** Modify or create a test script that uses the `slang_gaussian_rasterization` library to render an image using this malicious Gaussian dataset. Use either `api/gsplat_3dgs.py` or `api/inria_3dgs.py` as a base for integration.
    3. **Run with Memory Sanitizer:** Execute the test script with a memory error detection tool like AddressSanitizer (ASan). For example, if using Linux and compiling the Slang.D library with appropriate flags, run the Python script with `ASAN_OPTIONS=detect_leaks=0 python your_test_script.py`.
    4. **Observe for Memory Error:** Run the script and observe the output for AddressSanitizer error reports. A successful exploit will trigger an ASan error indicating an out-of-bounds write during the execution of the `generate_keys` kernel or in memory operations immediately following it. The error report will pinpoint the location of the memory corruption.
    5. **Analyze Crash (Optional):** If ASan is not available, run the script normally and observe for crashes or unusual behavior. While crashes might occur, they are less reliable for pinpointing the exact vulnerability than using a memory sanitizer. Examine core dumps or error logs if a crash occurs to investigate the cause.

By following these steps, you can demonstrate and confirm the buffer overflow vulnerability in the tile key generation process when processing a maliciously crafted Gaussian dataset.