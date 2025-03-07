## Combined Vulnerability List

### API Key Exposure through Misconfiguration
- Description:
    1. The FEABench project uses API keys to access external services like OpenAI and Anthropic for language model evaluations.
    2. These API keys are loaded from files specified by the constants `ANTHROPIC_PATH` and `OPENAI_PATH` in `common/constants.py`.
    3. Users might misconfigure these paths to point to publicly accessible files or mistakenly commit files containing API keys to the project repository.
    4. If an attacker gains access to these exposed API keys, they can impersonate the legitimate user, leading to unauthorized usage costs and potential access to sensitive data linked to the cloud service accounts.
- Impact:
    - Unauthorized access to cloud services accounts (OpenAI, Anthropic).
    - Unexpected financial charges due to illegitimate API usage.
    - Potential compromise of sensitive data if the affected accounts have access to such information.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - API keys are read from external files instead of being hardcoded directly in the code, as defined in `common/constants.py`. This is a limited mitigation, preventing keys from being directly embedded in the codebase but not preventing misconfiguration or accidental exposure of key files.
    - Location: The `get_api_key` function in `common/constants.py` handles reading keys from file paths defined as constants.
- Missing Mitigations:
    - **Secure API Key Management:** Implement robust API key management practices, such as utilizing environment variables or dedicated secret management services (like Google Secret Manager, AWS Secrets Manager, or HashiCorp Vault). Alternatively, user-specific configuration files that are explicitly excluded from version control could be used.
    - **Comprehensive Documentation and Best Practices:** Provide clear and detailed documentation for users on securely configuring API keys. This documentation should emphasize the significant risks of API key exposure and strongly recommend secure storage methods, explicitly warning against committing API key files to version control systems.
    - **Regular Security Audits and Code Reviews:** Conduct routine security audits and code reviews to proactively identify and address potential vulnerabilities related to API key handling and other security aspects of the project.
- Preconditions:
    - A user must clone the FEABench repository.
    - The user needs to configure the project to utilize OpenAI or Anthropic models, which necessitates providing API keys.
    - The user misconfigures `ANTHROPIC_PATH` or `OPENAI_PATH` in `common/constants.py` to reference an insecure location, or unintentionally commits API key files to a publicly accessible repository.
- Source Code Analysis:
    1. **File: `/code/common/constants.py`**:
        ```python
        ANTHROPIC_PATH = #
        OPENAI_PATH = #

        def get_api_key(model_type: str) -> str:
          if model_type == 'anthropic':
            return file_utils.file_open(ANTHROPIC_PATH, 'r').read().strip()
          elif model_type == 'openai':
            return file_utils.file_open(OPENAI_PATH, 'r').read().strip()
          else:
            raise ValueError('Unsupported model type: %s' % model_type)
        ```
        - The code initializes `ANTHROPIC_PATH` and `OPENAI_PATH` as constants, intended to store the file paths to the respective API keys.
        - The `get_api_key` function retrieves the API key by reading the content of the file specified by these paths, using `file_utils.file_open()`.
        - **Vulnerability:** If `ANTHROPIC_PATH` or `OPENAI_PATH` are configured to point to publicly accessible locations, or if the files at these paths are mistakenly added to version control, the API keys will be exposed.

    2. **File: `/code/llm_client_builder.py`**:
        ```python
        def build_lm_client(
            model_type: str,
            model_url: str,
            model_config: Any | None = None,
        ) -> LLMClient | llm_client.LLMClient:
          """Make client."""
          if model_type == 'anthropic':
            api_key = constants.get_api_key(model_type)
            return llm_client.AnthropicClient(
                model_name=model_url, api_key=api_key, **model_config
            )
          elif model_type == 'openai':
            # This calls the langfun wrapper around the OpenAI client.
            # Querying OpenAI directly raised a trawler error.
            api_key = constants.get_api_key('openai')
            return llm_client.OpenAILFClient(
                model_name=model_url, api_key=api_key, **model_config
            )
          # ...
        ```
        - The `build_lm_client` function utilizes `constants.get_api_key()` to fetch API keys based on the specified `model_type`.
        - These retrieved API keys are then passed as arguments during the instantiation of `llm_client.AnthropicClient` and `llm_client.OpenAILFClient`.

    3. **File: `/code/llm_client.py`**:
        ```python
        class OpenAILFClient(LLMClient):
          """Client for querying Openai endpoints via langfun."""

          def __init__(
              self,
              model_name: str,
              api_key: str, # API key is taken as constructor argument
              temperature: float = 0.0,
              top_k: float = 0.1,
              top_p: float = 0.2,
              stop: list[str] | None = None,
              max_tokens: int | None = None,
          ):
            """Initializes the Openai client."""
            self.model_name = model_name
            self.api_key = api_key # API key is stored as instance variable
            self.llm_engine = lf.core.llms.OpenAI(model=model_name, api_key=api_key)
            # ...

        class AnthropicClient(LLMClient):
          """Client for querying Anthropic inference endpoints."""

          def __init__(
              self,
              model_name: str,
              api_key: str, # API key is taken as constructor argument
              temperature: float = 0.0,
              top_k: float = 0.1,
              top_p: float = 0.2,
              stop: list[str] | None = None,
              max_tokens: int | None = None,
          ):
            """Initializes the Anthropic client."""
            self.model_name = model_name
            self.api_key = api_key # API key is stored as instance variable
            self.llm_engine = lf.core.llms.Anthropic(model_name=model_url, api_key=api_key)
            # ...
        ```
        - The `OpenAILFClient` and `AnthropicClient` classes in `llm_client.py` accept `api_key` as a constructor parameter and store it as an instance variable. This variable is subsequently used to initialize the LLM engines.

        ```mermaid
        graph LR
            A[/run_external_inference.py or run_external_inference_large.py/] --> B(llm_client_builder.build_lm_client)
            B --> C(constants.get_api_key)
            C --> D[/common/constants.py: ANTHROPIC_PATH or OPENAI_PATH/]
            D --> E[API Key File]
            B --> F(llm_client.AnthropicClient or llm_client.OpenAILFClient)
            F --> G[/llm_client.py: api_key parameter/]
            G --> H[LLM Engine (langfun)]
        ```

- Security Test Case:
    1. **Setup:**
        - Ensure that `anthropic_api_key.txt` and `openai_api_key.txt` files do not exist in the `/code/common/` directory.
        - Modify `/code/common/constants.py` to set `ANTHROPIC_PATH = '/tmp/anthropic_api_key.txt'` and `OPENAI_PATH = '/tmp/openai_api_key.txt'`. These paths are chosen to be unlikely to exist and are outside the project directory, simulating a misconfiguration scenario.
    2. **Execution:**
        - Run the script using the OpenAI model: `python common/run_external_inference.py --version=0 --prompt=prompt_v0_nosol.txt --model_type=openai --run=test_run --problems="comsol_267"`
        - Alternatively, run the script using the Anthropic model: `python common/run_external_inference_large.py --model_type=anthropic --trial=test_trial --subset=val`
    3. **Expected Outcome:**
        - The scripts will attempt to read API keys from the non-existent files `/tmp/anthropic_api_key.txt` or `/tmp/openai_api_key.txt`.
        - As these files are not created, the scripts should fail with a `FileNotFoundError` or a similar error message when trying to open these files in `common/constants.py` or during client initialization in `llm_client_builder.py`.
        - **Successful Exploitation Scenario (Illustrative):** In a scenario where a user mistakenly configures `ANTHROPIC_PATH` or `OPENAI_PATH` to point to a publicly accessible location (e.g., a public web server serving the API key in plaintext) or if they accidentally committed an API key file to a public GitHub repository and set the paths accordingly, executing the script would successfully load the API key from the misconfigured location. An attacker who discovers this misconfigured path or public repository would then gain unauthorized access to the API key.
    4. **Verification:**
        - Examine the error output. Confirm that the script fails to initiate because the API key file was not found, as expected in our test setup.
        - In a real-world misconfiguration scenario (which is harder to directly test without actual misconfiguration), successful script execution and usage of external LLM services would indicate that the API key was successfully loaded, potentially from a compromised or publicly accessible source.