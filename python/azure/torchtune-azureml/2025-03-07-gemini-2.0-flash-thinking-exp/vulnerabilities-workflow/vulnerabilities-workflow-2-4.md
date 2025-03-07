* Vulnerability name: Malicious YAML Configuration Injection
* Description:
    1. An attacker crafts a malicious YAML configuration file (e.g., `config.yaml` or any of the files in the `scripts/` directory).
    2. This malicious YAML file contains attacker-controlled configurations, such as modified Azure ML workspace details, compute cluster names, model paths, or other parameters that influence the behavior of the training, evaluation, or quantization processes.
    3. The attacker socially engineers a user to replace the legitimate configuration files with these malicious files. This could be achieved through phishing, providing the malicious file in a seemingly harmless package, or exploiting other social engineering techniques.
    4. The user, unaware of the malicious nature of the configuration files, proceeds to execute the provided notebooks (e.g., `training_sft.ipynb`, `training_dpo.ipynb`, `training_kd.ipynb`) or launcher scripts (e.g., `scripts/launcher_single.py`, `scripts/launcher_distributed.py`, etc.) from the project.
    5. These scripts parse the YAML configuration files and use the parameters within them to interact with the user's Azure ML environment, download models, configure training jobs, and perform other actions.
    6. Due to the lack of input validation and sanitization in the scripts, the attacker-controlled configurations from the malicious YAML file are executed without proper checks. This can lead to unintended and harmful actions within the user's Azure ML environment.
* Impact:
    - Unauthorized control over the user's Azure ML environment, allowing the attacker to manage resources and operations.
    - Financial impact on the user due to the potential deployment of expensive compute resources under attacker control.
    - Data security breaches, including unauthorized access, modification, or exfiltration of data stored within the Azure ML workspace.
    - Execution of arbitrary code within the Azure ML environment if the malicious configuration leads to the execution of untrusted code, for example, by loading a malicious model or manipulating training processes.
    - Reputational damage and loss of trust for the user and their organization if their Azure ML environment is compromised.
* Vulnerability rank: High
* Currently implemented mitigations:
    - None. The project, as provided, does not include any specific mitigations against malicious YAML configuration injection. It relies on the user to ensure the integrity and security of the configuration files they use.
* Missing mitigations:
    - Input validation and sanitization: Implement rigorous validation for all configuration parameters read from YAML files. This should include checking data types, allowed values, and formats to prevent unexpected or malicious inputs from being processed.
    - Principle of least privilege: Design the scripts and Azure ML operations to adhere to the principle of least privilege. Ensure that the scripts only request and utilize the minimum necessary permissions within Azure ML to perform their intended functions, limiting the potential damage from malicious configurations.
    - Secure defaults and warnings: Provide secure default configurations for all YAML files. Include clear warnings in the documentation and README files about the risks of using untrusted or modified configuration files. Emphasize the importance of using configuration files only from trusted sources.
    - Configuration integrity checks: Consider implementing mechanisms to verify the integrity and authenticity of configuration files. This could involve using checksums, digital signatures, or other methods to ensure that the configuration files have not been tampered with.
    - User education and awareness: Provide comprehensive documentation and tutorials that educate users about the security risks associated with using untrusted configuration files. Promote security best practices, such as downloading project files and configurations only from official and trusted repositories.
* Preconditions:
    - The attacker must successfully socially engineer the user into downloading and using a malicious YAML configuration file, replacing a legitimate one in the project.
    - The user must then execute one of the project's notebooks or launcher scripts that relies on these configuration files.
    - The user must have an active Azure ML workspace and credentials configured, as the malicious configurations target actions within this environment.
* Source code analysis:
    - The launcher scripts (`launcher_single.py`, `launcher_distributed.py`, `launcher_single_kd.py`, `launcher_distributed_kd.py`) are the primary entry points that parse and utilize YAML configuration files.
    - In these scripts, the argument parsing logic includes options to specify YAML configuration files, such as `--tune_finetune_yaml`, `--tune_eval_yaml`, and `--tune_quant_yaml`. For example, in `launcher_single.py`:
    ```python
    parser = argparse.ArgumentParser()
    ...
    parser.add_argument(
        "--tune_finetune_yaml", type=str, default="lora_finetune_phi3.yaml"
    )
    args = parser.parse_known_args()
    ```
    - The scripts then read the content of the YAML files specified by these arguments using `Path(args.tune_finetune_yaml).open().read()`.
    - Jinja2 templating is used to dynamically modify these YAML files based on other script arguments and environment settings:
    ```python
    jinja_env = jinja2.Environment()
    template = jinja_env.from_string(Path(args.tune_finetune_yaml).open().read())
    Path(args.tune_finetune_yaml).open("w").write(
        template.render(...)
    )
    ```
    - Finally, the `tune run` command is constructed and executed, passing the (potentially modified) YAML file as a configuration:
    ```python
    full_command = f"tune run {args.tune_recipe} --config {args.tune_finetune_yaml}"
    run_command(full_command)
    ```
    - The critical point is the absence of any validation or sanitization of the configuration parameters extracted from the YAML files before they are used in constructing commands or interacting with Azure ML. The scripts directly trust the content of these files, making them vulnerable to injection attacks if a malicious YAML file is provided.
* Security test case:
    1. **Setup:**
        - Set up an Azure ML workspace and ensure you have the necessary credentials to run the provided example project.
        - Have a clean copy of the original project files to compare against.
    2. **Create Malicious `config.yaml`:**
        - Create a modified `config.yaml` file. In this malicious file, alter critical parameters to demonstrate the vulnerability. For example:
            - Change `azure_compute_cluster_name` under `train` to the name of an extremely expensive compute cluster available in your Azure subscription (if you have one, or a name that you know will cause an error but highlight the config is read).
            - Modify `HF_MODEL_NAME_OR_PATH` under `config` to point to a non-existent or malicious Hugging Face model name.
            - Alter `azure_env_name` or other Azure ML resource names to something unexpected to observe if these names are used in Azure ML operations.
        - Example malicious `config.yaml` (excerpt):
        ```yaml
        config:
            ...
            HF_MODEL_NAME_OR_PATH: "attacker-org/totally-malicious-model"
            ...
        train:
            ...
            azure_compute_cluster_name: "expensive-cluster-that-does-not-exist"
            azure_compute_cluster_size: "Standard_NC96ads_A100_v4"
            ...
        ```
    3. **Replace Legitimate `config.yaml`:**
        - Replace the original `config.yaml` file in your project directory with the malicious `config.yaml` file you created.
    4. **Execute Launcher Script:**
        - Open a terminal in your project directory and execute one of the launcher scripts, for example, `scripts/launcher_single.py`. Ensure you provide the necessary arguments, including your Hugging Face token if required.
        ```bash
        cd code/scripts
        python launcher_single.py --hf_token YOUR_HF_TOKEN
        ```
    5. **Observe Azure ML Environment and Script Output:**
        - Monitor the Azure ML workspace through the Azure portal or CLI. Check if the script attempts to create or use the compute cluster specified in your malicious `config.yaml` (`expensive-cluster-that-does-not-exist` in the example).
        - Examine the script's output logs for any error messages related to the malicious configurations, such as failures to find the specified compute cluster or model.
        - If the script attempts to run a job, observe if it uses the modified configurations. Even if the job fails due to incorrect configurations, this demonstrates that the malicious configurations were indeed parsed and used by the script.
    6. **Expected Results:**
        - The script should attempt to use the configurations provided in the malicious `config.yaml`.
        - You should observe attempts to interact with Azure ML using the attacker-specified names or parameters.
        - Errors might occur if the configurations are invalid (e.g., non-existent compute cluster), but the key is to demonstrate that the malicious configurations are processed and acted upon by the scripts, highlighting the vulnerability.
    7. **Cleanup:**
        - After testing, restore the original `config.yaml` file to prevent unintended consequences in your Azure ML environment.
        - Delete any Azure ML resources that might have been inadvertently created or modified during the test, especially if you used a configuration that could potentially create expensive resources.

This security test case will demonstrate that by providing a maliciously crafted `config.yaml` file, an attacker can influence the behavior of the project's scripts and cause them to perform actions within the user's Azure ML environment based on attacker-defined parameters, thus proving the Malicious YAML Configuration Injection vulnerability.