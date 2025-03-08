## Vulnerability Report

### Integer Overflow in AtomicGrid atom_positions allocation

- Description:
  1. The `AtomicGrid.from_proto` method in `/code/putting_dune/microscope_utils.py` deserializes `AtomicGrid` objects from protobuf.
  2. It reads the number of atoms from the protobuf message (`proto_grid.atoms`).
  3. A malicious `.tfrecords` file with a very large number of atoms can cause an integer overflow when calculating the size of the `atom_positions` numpy array (e.g., `(num_atoms, 2)`).
  4. This overflow leads to allocating a smaller buffer for `atom_positions`.
  5. When populating this buffer with atom positions, the code writes beyond the allocated buffer, causing a buffer overflow.
  6. An attacker crafts a `.tfrecords` file with a `Trajectory` containing a `MicroscopeObservation` with an `AtomicGrid` protobuf message specifying a huge number of atoms.
  7. This malicious file is input to `align_trajectories.py` or `train_rate_learner.py` via `--source_path`.
  8. Parsing the file with `pdio.read_records` calls `AtomicGrid.from_proto`, triggering the integer overflow and buffer overflow.

- Impact:
  - Memory corruption: Overwriting memory beyond the `atom_positions` buffer corrupts adjacent memory.
  - Potential for arbitrary code execution: Buffer overflows can be exploited for code execution by overwriting return addresses or function pointers. Even without direct code execution, memory corruption is a critical security issue.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
  - None: The code lacks input validation for the number of atoms and directly allocates memory based on the protobuf message value without overflow checks.

- Missing Mitigations:
  - Input validation: Validate the number of atoms from the protobuf message in `AtomicGrid.from_proto` to ensure it's within safe limits and representable by `np.int32` or `np.int64` before memory allocation.
  - Error handling: Implement error handling in `AtomicGrid.from_proto` to catch integer overflows or memory allocation errors and prevent program crashes or corrupted memory usage.

- Preconditions:
  - The attacker must provide a malicious `.tfrecords` file to `align_trajectories.py` or `train_rate_learner.py`. This is possible via the `--source_path` command-line argument.

- Source Code Analysis:
  ```python
  File: /code/putting_dune/microscope_utils.py
  def from_proto(cls, proto_grid: putting_dune_pb2.AtomicGrid) -> 'AtomicGrid':
    """Creates an AtomicGrid from a proto."""
    num_atoms = len(proto_grid.atoms)  # Vulnerable point: Reads num_atoms directly from proto

    atom_positions = np.empty((num_atoms, 2), dtype=np.float32) # Vulnerable point: Allocates array based on potentially malicious num_atoms
    atomic_numbers = np.empty(num_atoms, dtype=np.int32) # Vulnerable point: Allocates array based on potentially malicious num_atoms

    for i, atom in enumerate(proto_grid.atoms): # Vulnerable point: Loop iterates based on potentially malicious num_atoms
      atom_positions[i, 0] = atom.position.x
      atom_positions[i, 1] = atom.position.y # Potential Buffer Overflow: Writes to potentially undersized buffer
      atomic_numbers[i] = atom.atomic_number # Potential Buffer Overflow: Writes to potentially undersized buffer

    return cls(atom_positions, atomic_numbers)
  ```

  **Visualization:**

  ```
  [Malicious TFRecord] --> read_records (putting_dune/io.py)
                         |
                         V
  [proto_grid: AtomicGrid with large num_atoms] --> from_proto (putting_dune/microscope_utils.py)
                                                    |
                                                    V
  num_atoms = len(proto_grid.atoms) # Large value from malicious input
  atom_positions = np.empty((num_atoms, 2), dtype=np.float32) # Potentially small buffer due to integer overflow
  atomic_numbers = np.empty(num_atoms, dtype=np.int32) # Potentially small buffer due to integer overflow
  for i in range(num_atoms):
      atom_positions[i, ...] = ... # Buffer Overflow: Write beyond allocated buffer
      atomic_numbers[i] = ...     # Buffer Overflow: Write beyond allocated buffer
  ```

- Security Test Case:
  1. Create a malicious protobuf message `malicious_grid_proto` of type `putting_dune_pb2.AtomicGrid`.
  2. Set `malicious_grid_proto.atoms` to contain a very large number of atoms, exceeding integer limits that could cause an overflow when multiplied by 2 for `atom_positions` array allocation. Programmatically add many `putting_dune_pb2.Atom` messages to `malicious_grid_proto.atoms`.
  3. Create a `Trajectory` protobuf message `malicious_trajectory_proto` and set its `observations` field to contain a `MicroscopeObservation` protobuf message including `malicious_grid_proto` in its `grid` field.
  4. Serialize `malicious_trajectory_proto` to a `.tfrecords` file named `malicious.tfrecords`.
  5. Run `align_trajectories.py` (or `train_rate_learner.py`) with `--source_path malicious.tfrecords`.
  6. Observe program behavior for crashes due to memory corruption or errors related to memory allocation, indicating the vulnerability. Use memory debugging tools like AddressSanitizer for robust verification of out-of-bounds memory access and buffer overflow.