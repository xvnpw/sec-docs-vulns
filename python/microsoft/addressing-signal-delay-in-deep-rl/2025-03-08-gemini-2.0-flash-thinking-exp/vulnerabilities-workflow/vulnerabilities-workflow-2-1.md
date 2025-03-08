### Vulnerability List

* Vulnerability Name: Wandb API Key Exposure via `.env` File
* Description:
    1. The project instructs users to store their Weights & Biases (wandb) API key in a `.env` file at the project root.
    2. Users might inadvertently commit or expose this `.env` file to public repositories (e.g., on GitHub) or insecure cloud storage.
    3. An attacker can find publicly exposed `.env` files by searching on platforms like GitHub, using search queries such as "WANDB_API_KEY" and file extensions like ".env".
    4. Once the attacker finds a publicly accessible `.env` file containing the `WANDB_API_KEY`, they can copy the API key.
    5. With the stolen API key, the attacker can gain unauthorized access to the victim's Wandb account.
* Impact:
    1. **Unauthorized Access to Experiment Data:** The attacker gains full read and write access to the victim's experiment logs, project data, and potentially models stored on Wandb.
    2. **Data Manipulation and Spoofing:** The attacker could manipulate experiment data, leading to misleading results and potentially compromising research integrity. They could also inject false experiment data.
    3. **Resource Consumption:** The attacker might use the victim's Wandb account resources (storage, compute if applicable) for their own purposes, potentially incurring costs for the victim.
    4. **Account Takeover (in some scenarios):** Depending on Wandb's account security policies and the scope of API key permissions, in some cases, an attacker might be able to escalate access and potentially gain more control over the victim's Wandb account beyond just API access.
* Vulnerability Rank: High
* Currently Implemented Mitigations:
    * The project provides instructions to store the Wandb API key in a `.env` file, but it does not include any explicit warnings or security guidance about the risks of exposing this file.
    * The `.devcontainer/Dockerfile` and `.devcontainer.json` files are provided for development environment setup, which can help isolate the development environment but do not directly mitigate the risk of `.env` file exposure if users don't use or misconfigure these tools.
* Missing Mitigations:
    1. **Security Warning in README:** Add a prominent warning in the `README.md` file about the security risks of storing API keys in `.env` files and the importance of not committing `.env` files to public repositories.
    2. **`.gitignore` Configuration:** Include `.env` in the `.gitignore` file by default to prevent accidental commits of the `.env` file to Git repositories. While users can modify or remove `.gitignore`, including it by default serves as a strong suggestion.
    3. **Alternative Secure Key Storage:** Recommend more secure methods for handling API keys, such as:
        * **Environment Variables (System-level or User-level):** Instruct users to set `WANDB_API_KEY` as a system or user environment variable instead of relying on a `.env` file. This way, the key is not stored within the project directory.
        * **Wandb CLI Authentication:** Encourage users to authenticate with Wandb using the `wandb login` command, which securely stores the API key in the Wandb CLI configuration without needing a `.env` file.
        * **Secret Management Tools:** For more advanced users or in production environments, suggest using dedicated secret management tools or services to handle API keys securely.
    4. **Documentation on Secure Practices:** Create a dedicated section in the documentation (or expand the "Logging with Wandb" section in `README.md`) that comprehensively explains secure API key handling practices, emphasizing the risks of exposure and providing step-by-step instructions for recommended secure alternatives.
* Preconditions:
    1. User follows the project's instructions to use Wandb logging and creates a `.env` file.
    2. User stores their actual Wandb API key in the `.env` file as instructed: `WANDB_API_KEY="YOUR_WANDB_API_KEY"`.
    3. User inadvertently exposes the `.env` file, for example by:
        * Committing the `.env` file to a public Git repository.
        * Uploading the `.env` file to a publicly accessible cloud storage.
        * Leaving the `.env` file in a publicly accessible location on a server.
* Source Code Analysis:
    1. **File: `/code/README.md`**:
        * In the "Logging with Wandb" section, the `README.md` provides the following instruction:
        ```markdown
        ## Logging with Wandb

        simply add `wandb.mode=online` in the python executing parameter as the following:

        ```
        python src/entry.py \
        	experiment=pred_detach \
        	env.name=Ant-v4 \
        	env.delay=0 \
        	wandb.mode=online
        ```

        Create a file named as `.env` in the project root and put the following in it, your wandb key would be automatically read

        ```latex
        WANDB_API_KEY="36049{change_to_your_wandb_key}215a1d76"
        ```
        * This instruction explicitly tells users to create a `.env` file and store their `WANDB_API_KEY` within it, placing the file at the project root, which is often the same directory where Git repositories are initialized.
        * There is no security warning associated with this instruction, nor guidance to add `.env` to `.gitignore` or use more secure methods.
    2. **File: `/code/src/entry.py`**:
        * The `initialize_wandb` function in `entry.py` is responsible for initializing Wandb. It reads the `WANDB_API_KEY` from environment variables, which is the standard way `.env` files are used with libraries like `dotenv`.
        ```python
        def initialize_wandb(cfg):
            # ...
            wandb.init(
                project=cfg.task_name,
                tags=cfg.tags,
                config=utils.config_format(cfg),
                dir=wandb_dir,
                mode=cfg.wandb.mode
            )
            return wandb_dir
        ```
        * This code confirms that the project is designed to read the `WANDB_API_KEY` from environment variables, making the `.env` file approach functional as described in `README.md`.

* Security Test Case:
    1. **Setup:**
        * Assume a user has followed the instructions and created a `.env` file in the project root with their actual Wandb API key: `WANDB_API_KEY="YOUR_ACTUAL_WANDB_API_KEY"`.
        * Assume the user has inadvertently made their project repository (including the `.env` file) publicly accessible on GitHub.
        * Assume an attacker has access to the public GitHub repository URL.
    2. **Attacker Action - Find Exposed `.env` file:**
        * The attacker uses GitHub search to find repositories containing `.env` files with "WANDB_API_KEY". A search query like `"WANDB_API_KEY filename:.env"` could be used.
        * The attacker locates the user's repository in the search results and navigates to the repository on GitHub.
        * The attacker directly accesses the `.env` file within the repository (if it is committed).
        * The attacker inspects the content of the `.env` file and finds the line `WANDB_API_KEY="YOUR_ACTUAL_WANDB_API_KEY"`, copying the API key value.
    3. **Attacker Action - Unauthorized Wandb Access:**
        * The attacker, on their local machine, sets the environment variable `WANDB_API_KEY` to the stolen API key value: `export WANDB_API_KEY="YOUR_ACTUAL_WANDB_API_KEY"`.
        * The attacker clones the project repository to their local machine.
        * The attacker runs the `src/entry.py` script with Wandb logging enabled (e.g., `python src/entry.py experiment=sac wandb.mode=online`).
    4. **Verification:**
        * The script executes, and experiment logs are successfully uploaded to the *victim's* Wandb account, as configured by the stolen API key.
        * The attacker can now access the victim's Wandb dashboard and see the newly created run, along with any existing projects and runs associated with that API key, confirming unauthorized access.