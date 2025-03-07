* Vulnerability Name: Code Injection via Malicious Custom Block

* Description:
    1. A threat actor crafts a malicious Python block (custom layer) designed to execute arbitrary code.
    2. The attacker registers this malicious block within the Model Search framework using the `@register_block` decorator.
    3. The attacker tricks a user into including the `lookup_name` of this malicious block in their `blocks_to_use` list within the `PhoenixSpec` configuration.
    4. When the user initiates a model search, the Model Search framework, during model building, looks up and instantiates the block based on the provided `lookup_name`.
    5. The framework calls the `build` method of the malicious block, which executes the attacker's injected code.

* Impact:
    - **Critical**: Arbitrary code execution on the machine running the Model Search framework. This could lead to complete system compromise, data exfiltration, or other malicious activities.

* Vulnerability Rank: Critical

* Currently Implemented Mitigations:
    - None: The code provides mechanisms for registering and using custom blocks without any input validation or sandboxing.

* Missing Mitigations:
    - **Input Validation**: The framework should validate the `blocks_to_use` configuration to ensure that only trusted and verified blocks are used. This could involve a whitelist of approved blocks or a mechanism to verify the integrity and safety of custom blocks.
    - **Sandboxing/Isolation**: Custom blocks should be executed in a sandboxed or isolated environment to prevent them from accessing or compromising the host system. This could involve using secure containers or virtual machines to run the model building and training processes.
    - **Code Review/Security Audit**:  A thorough security audit and code review of the block registration and model building components is necessary to identify and address potential code injection vulnerabilities.
    - **Principle of Least Privilege**: The user running Model Search should operate with the minimum necessary privileges to reduce the impact of potential code injection attacks.

* Preconditions:
    1. The attacker must be able to create and register a malicious block within the Model Search framework.
    2. A user must be tricked into using the `lookup_name` of the malicious block in their `PhoenixSpec` configuration.
    3. The Model Search framework must be executed to build and utilize the model with the malicious custom block.

* Source Code Analysis:
    1. **`File: /code/registry.py`**:
        - The `@register` decorator in `registry.py` (and consequently `@register_block` in `block.py`) allows registration of arbitrary classes as blocks.
        - There is no validation or sanitization of the registered classes or their initialization arguments.
    2. **`File: /code/block.py`**:
        - The `Block` class defines the interface for custom blocks, including the `build` method, which is intended for model construction logic.
        - The `build` method of custom blocks is directly invoked by the framework without any security checks.
    3. **`File: /code/block_builder.py`**:
        - The `Blocks` class uses the registry to look up and instantiate blocks based on `BlockType` enums, which are derived from registered block names.
    4. **`File: /code/phoenix.py`**:
        - The `Phoenix` class uses `BlockBuilder` to create model components based on the `PhoenixSpec`, including the `blocks_to_use` configuration.
        - The `_make_model_fn` and `keras_model_builder` methods orchestrate the model building process, which involves instantiating and utilizing registered blocks.
    5. **`File: /code/configs/dnn_config.pbtxt` & `File: /code/configs/cnn_config.pbtxt`**:
        - These configuration files define default search spaces, including `blocks_to_use`.
        - Users are instructed in `README.md` to modify these configurations and add their own registered blocks, opening the door for malicious block inclusion.
    6. **Visualization**:
        ```mermaid
        graph LR
        A[PhoenixSpec Configuration] --> B(Parse Configuration);
        B --> C{Is custom block lookup_name in blocks_to_use?};
        C -- Yes --> D[Registry Lookup Block Class];
        D --> E[Instantiate Block];
        E --> F[Call Block.build()];
        F --> G[Execute Arbitrary Code];
        ```

* Security Test Case:
    1. **Create a malicious block**:
        - Create a Python file (e.g., `malicious_block.py`) with the following content:

        ```python
        from model_search import block
        from model_search import registry
        import subprocess

        @registry.register_block(lookup_name='MALICIOUS_BLOCK', enum_id=999)
        class MaliciousBlock(block.Block):
          def build(self, input_tensors, is_training, lengths=None):
            subprocess.run(["touch", "/tmp/pwned"]) # Malicious command
            return input_tensors + [input_tensors[-1]]
          @property
          def is_input_order_important(self):
            return False
        ```

    2. **Register the malicious block**:
        - Modify `model_search/blocks.py` to import and include `malicious_block.py`.  For example, add `from . import malicious_block` at the beginning of the file.

    3. **Create a PhoenixSpec configuration**:
        - Create or modify a `PhoenixSpec` configuration file (e.g., `malicious_config.pbtxt`) to include `MALICIOUS_BLOCK` in `blocks_to_use`:

        ```pbtxt
        problem_type: DNN
        search_type: NONADAPTIVE_RANDOM_SEARCH
        blocks_to_use: "MALICIOUS_BLOCK"
        ```

    4. **Run Model Search with the malicious configuration**:
        - Execute the Model Search binary (e.g., `oss_trainer.py`) using the malicious configuration:

        ```bash
        python model_search/oss_trainer.py \
          --phoenix_spec_filename=malicious_config.pbtxt \
          --model_dir=/tmp/malicious_run \
          --experiment_name=malicious_experiment \
          --experiment_owner=attacker
        ```

    5. **Verify code execution**:
        - Check if the file `/tmp/pwned` has been created. If it exists, the code injection vulnerability is confirmed.