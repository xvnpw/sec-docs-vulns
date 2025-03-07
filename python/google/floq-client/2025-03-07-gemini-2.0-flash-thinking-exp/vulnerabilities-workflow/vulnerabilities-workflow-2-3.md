### Vulnerability List:

- Vulnerability Name: API Key Exposure in Command Line Arguments and Sample Code
- Description:
    1. The Floq client CLI script (`scripts/cli.py`) is designed to accept the API key as a command-line argument.
    2. When a user executes a command using the CLI, the command, including the API key, is recorded in the shell history.
    3. An attacker who gains unauthorized access to the user's system can read the shell history files (e.g., `.bash_history`, `.zsh_history`).
    4. The attacker can then extract the API key from the command history.
    5. Additionally, the sample code files in the `samples/` directory contain hardcoded placeholder API keys (`API_KEY = "api_key"`).
    6. If a user mistakenly replaces the placeholder with their actual API key and commits this code to a public repository, the API key becomes publicly accessible.
    7. An attacker can find these exposed API keys by searching public repositories or through other means of code sharing.
    8. With a valid API key, an attacker can authenticate to the Floq service as the legitimate user.
    9. The attacker can then submit quantum circuits, access job results, manage jobs queue and TPU worker, potentially incurring costs and accessing sensitive data associated with the compromised user's account.
- Impact:
    - Unauthorized access to the Floq quantum computing service.
    - Potential for resource abuse and financial impact on the legitimate user's account.
    - Exposure of potentially sensitive quantum computation results to unauthorized parties.
    - Ability for the attacker to control and manipulate the user's jobs queue and TPU worker.
- Vulnerability Rank: Medium
- Currently Implemented Mitigations:
    - None. The current implementation in `scripts/cli.py` explicitly takes the API key as a command-line argument. The sample codes also show API keys as hardcoded strings. The README provides examples using "my_api_key" as a placeholder, but lacks explicit warnings against hardcoding or using CLI arguments for sensitive credentials.
- Missing Mitigations:
    - **CLI Script:**
        - Implement reading the API key from environment variables instead of command-line arguments. This prevents the API key from being stored in shell history.
        - Update the CLI documentation and help messages to instruct users to set the API key as an environment variable.
    - **Sample Code:**
        - Modify sample scripts to load the API key from environment variables or a configuration file instead of hardcoding it.
        - Add prominent comments in all sample code files, explicitly warning against hardcoding API keys and recommending the use of environment variables or secure configuration methods.
        - Before committing code, ensure placeholder API keys in samples are either removed or commented out to prevent accidental exposure.
- Preconditions:
    - For CLI exposure:
        - A user must execute the `floq-client` CLI script and provide the API key as a command-line argument.
        - An attacker must gain access to the user's shell history files.
    - For Sample Code exposure:
        - A user must hardcode their actual API key into one of the sample code files.
        - The user must then expose this modified sample code, for example, by committing it to a public repository or sharing it insecurely.
- Source Code Analysis:
    - `scripts/cli.py`:
        ```python
        parser = argparse.ArgumentParser(
            "Floq CLI client",
            description="A helper script that controls Floq service resources.",
        )
        parser.add_argument("api_key", type=str, help="Floq service API key")
        ```
        This code snippet shows that the `api_key` is taken directly as a command-line argument using `parser.add_argument("api_key", ...)`. This makes the API key visible in shell history and process listings.
    - `samples/simulate_samples.py`, `samples/jobs_queue.py`, `samples/worker_manager_async.py`, `samples/simulate_expectation_values.py`, `samples/worker_manager.py`, `samples/pennylane.py`:
        ```python
        API_KEY = "api_key"
        client = floq.client.CirqClient(API_KEY)
        ```
        In each of these sample files, the `API_KEY` is defined as a string literal within the code. This represents a hardcoded credential, making it vulnerable to exposure if the code is shared or publicly accessible.

- Security Test Case:
    1. **Scenario 1: CLI Command History Exposure**
        - **Setup:** Assume an attacker has gained read access to the victim's shell history files (e.g., through malware or social engineering).
        - **Action:**
            - The victim executes a `floq-client` command, including their API key as a command-line argument:
              ```bash
              floq-client YOUR_API_KEY jobs display
              ```
            - The attacker accesses the victim's shell history file (e.g., `~/.bash_history`).
            - The attacker searches the history file and finds the command containing the API key.
            - The attacker extracts the API key (`YOUR_API_KEY`).
            - From the attacker's own machine, they use the extracted API key to execute a `floq-client` command:
              ```bash
              floq-client YOUR_API_KEY jobs display
              ```
        - **Expected Result:** The attacker successfully executes the command and retrieves information from the Floq service, authenticated as the victim, demonstrating unauthorized access due to API key exposure in command history.

    2. **Scenario 2: Sample Code Hardcoding and Public Repository Exposure**
        - **Setup:** Assume a victim user mistakenly hardcodes their real API key into the `samples/simulate_samples.py` file and commits this modified file to a public GitHub repository. The attacker is an external user monitoring public GitHub repositories.
        - **Action:**
            - The victim modifies `samples/simulate_samples.py`:
              ```python
              API_KEY = "YOUR_ACTUAL_API_KEY" # Victim mistakenly hardcodes API key
              import cirq
              import floq.client

              def main() -> None:
                  """Script entry point."""
                  qubits = cirq.LineQubit.range(1)
                  circuit = cirq.Circuit([cirq.X(qubits[0]), cirq.measure(qubits[0])])

                  client = floq.client.CirqClient(API_KEY)
                  result = client.simulator.run(circuit)
                  print(result)


              if __name__ == "__main__":
                  main()
              ```
            - The victim commits and pushes this file to a public GitHub repository.
            - The attacker searches GitHub using keywords like `"API_KEY = \"YOUR_ACTUAL_API_KEY\""` or `"floq.client.CirqClient(API_KEY)"` in public repositories.
            - The attacker locates the victim's repository and finds the hardcoded API key in `samples/simulate_samples.py`.
            - The attacker extracts the API key (`YOUR_ACTUAL_API_KEY`).
            - From the attacker's own machine, they use the extracted API key to execute a `floq-client` command:
              ```bash
              floq-client YOUR_ACTUAL_API_KEY jobs display
              ```
        - **Expected Result:** The attacker successfully executes the command and interacts with the Floq service using the victim's API key, demonstrating unauthorized access due to API key exposure in publicly accessible sample code.