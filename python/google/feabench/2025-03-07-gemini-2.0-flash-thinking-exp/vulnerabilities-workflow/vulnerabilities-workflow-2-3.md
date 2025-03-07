### Vulnerability List

- Vulnerability Name: API Key Exposure through Misconfiguration
- Description:
    1. The FEABench project utilizes API keys to access services like OpenAI and Anthropic for language model evaluations.
    2. These API keys are read from files specified in `common/constants.py` (`ANTHROPIC_PATH`, `OPENAI_PATH`).
    3. If users misconfigure the paths in `common/constants.py` to point to publicly accessible files or accidentally commit files containing API keys into the repository, these keys can be unintentionally exposed.
    4. An attacker gaining access to these exposed API keys can then impersonate the legitimate user and incur unauthorized usage costs or access sensitive data associated with the cloud service accounts linked to these keys.
- Impact:
    - Unauthorized access to cloud services (OpenAI, Anthropic) accounts.
    - Financial losses due to unauthorized API usage.
    - Potential data breaches if the compromised accounts have access to sensitive information.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - API keys are read from files instead of being hardcoded in the scripts (`common/constants.py`). This is a partial mitigation as it avoids accidental inclusion in the code itself, but doesn't prevent misconfiguration or accidental committing of key files.
    - Location: `common/constants.py` - `get_api_key` function reads keys from file paths defined as constants.
- Missing Mitigations:
    - **Secure API Key Management:** Implement secure methods for handling API keys, such as using environment variables, dedicated secret management services (e.g., Google Secret Manager, AWS Secrets Manager, HashiCorp Vault), or user-specific configuration files that are explicitly excluded from version control.
    - **Documentation and Best Practices:** Provide clear documentation to users on how to securely configure API keys, emphasizing the risks of exposure and recommending secure storage practices. This documentation should explicitly warn against committing API key files to version control.
    - **Security Audits and Code Reviews:** Regularly conduct security audits and code reviews to identify potential vulnerabilities related to API key handling and other security aspects of the project.
- Preconditions:
    - User clones the FEABench repository.
    - User needs to configure the project to use OpenAI or Anthropic models, requiring API keys.
    - User misconfigures `ANTHROPIC_PATH` or `OPENAI_PATH` in `common/constants.py` to point to an insecure location or accidentally commits API key files to a public repository.
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
        - The code defines `ANTHROPIC_PATH` and `OPENAI_PATH` as constants, intended to store file paths to API keys.
        - The `get_api_key` function reads the API key from the file specified by these paths using `file_utils.file_open()`.
        - **Vulnerability:** If `ANTHROPIC_PATH` or `OPENAI_PATH` are set to point to publicly accessible locations or if the files at these paths are accidentally committed to version control, the API keys will be exposed.

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
        - The `build_lm_client` function uses `constants.get_api_key()` to retrieve API keys based on the `model_type`.
        - These API keys are then passed as arguments to the constructors of `llm_client.AnthropicClient` and `llm_client.OpenAILFClient`.

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
        - `OpenAILFClient` and `AnthropicClient` classes in `llm_client.py` take `api_key` as a constructor argument and store it as an instance variable, which is then used to initialize the LLM engines.

        **Visualization:**

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
        - Do not create `anthropic_api_key.txt` and `openai_api_key.txt` files in `/code/common/`.
        - Modify `/code/common/constants.py` to set `ANTHROPIC_PATH = '/tmp/anthropic_api_key.txt'` and `OPENAI_PATH = '/tmp/openai_api_key.txt'`. These paths are unlikely to exist and are outside the project directory, simulating misconfiguration.
    2. **Execution:**
        - Run `python common/run_external_inference.py --version=0 --prompt=prompt_v0_nosol.txt --model_type=openai --run=test_run --problems="comsol_267"`
        - Or run `python common/run_external_inference_large.py --model_type=anthropic --trial=test_trial --subset=val`
    3. **Expected Outcome:**
        - The scripts should attempt to read API keys from `/tmp/anthropic_api_key.txt` or `/tmp/openai_api_key.txt`.
        - Since these files are not created, the scripts will likely fail with a `FileNotFoundError` or similar error when trying to open these files in `common/constants.py` or during client initialization in `llm_client_builder.py`.
        - **Successful Exploitation Scenario (if misconfiguration is different):** If a user were to mistakenly set `ANTHROPIC_PATH` or `OPENAI_PATH` to point to a publicly accessible location (e.g., a publicly accessible web server returning the API key in plaintext) or if they accidentally committed a file containing their API key to a public GitHub repository and pointed the paths there, then running the script would successfully read the API key from the misconfigured location. An attacker who gains access to this misconfigured path or public repository would then have access to the API key.
    4. **Verification:**
        - Observe the error output. Confirm that the script fails to start due to API key file not found (in our test setup).
        - In a real-world misconfiguration scenario (not easily testable directly without actual misconfiguration), if the script were to run successfully and use external LLM services, it would indicate that the API key was successfully loaded, potentially from a compromised or publicly accessible location.

This vulnerability highlights the risk of unintentional API key exposure due to misconfiguration and lack of secure API key management practices in the project.