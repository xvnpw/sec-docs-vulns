## Vulnerability Report

### 1. Insecure Key Generation due to Weak Seed Usage

- **Description:**
    1. The Jaxite library relies on user-provided seeds for random number generators when creating cryptographic keys, including LWE secret keys, RLWE secret keys, RGSW secret keys, bootstrapping keys, and key switching keys.
    2. The `README.md` example code for `jaxite_bool` demonstrates key generation using a fixed, predictable seed (`seed=1`).  Additionally, the `PseudorandomSource` class, used in various test cases and potentially by users copying test code, defaults to `seed=1` if no seed is explicitly provided.
    3. If developers copy and paste example code directly from the `README.md` or test files into production systems, or if they use the default `PseudorandomSource` without changing the seed, the encryption keys become predictable.
    4. An attacker who knows or discovers this seed (or the default seed behavior) can regenerate the same keys.
    5. By predicting the keys, the attacker can decrypt any data encrypted using these keys, compromising the confidentiality of the homomorphic encryption scheme.
    6. **Step-by-step trigger:**
        1. A user implements Jaxite in their application, potentially reusing example code or using default configurations, and fails to replace the insecure `seed=1` (or default seed of `PseudorandomSource`) with a cryptographically secure seed.
        2. The user encrypts sensitive data using the generated client keys and performs homomorphic operations using the server keys.
        3. An attacker gains access to the ciphertext and potentially the user's key generation code (e.g., through a public code repository, exposed configurations, or by social engineering).
        4. The attacker identifies the usage of the weak seed (e.g., `seed=1` in code or default seed assumption).
        5. The attacker regenerates the same cryptographic keys using the weak seed.
        6. The attacker decrypts the ciphertext using the compromised client keys, gaining access to the sensitive data.

- **Impact:**
    - **Critical**: Complete compromise of the homomorphic encryption security.
    - An attacker can decrypt all data encrypted using keys derived from weak or default seeds.
    - Loss of confidentiality and potential data breach, leading to severe consequences for data privacy and security.

- **Vulnerability Rank:** Critical

- **Currently Implemented Mitigations:**
    - **Documentation in `README.md` warning:** The `README.md` file includes a comment within the example code: `# Note: In real applications, a cryptographically secure seed needs to be # used.` This serves as a documentation-based warning against using insecure seeds and highlights the example usage of `seed=1` as insecure and for demonstration purposes only.
    - **Flexibility to use secure RNGs:** The code allows users to provide their own `RandomSource` implementations and seeds, offering flexibility to use cryptographically secure RNGs.

- **Missing Mitigations:**
    - **Stronger Warnings in Documentation:**  The documentation, especially the Quick Start section in `README.md`, should prominently display a clear and strong warning, beyond a simple comment, against using predictable seeds in production. This warning should explicitly state the security risks and consequences of using weak seeds.
    - **Secure Key Generation Guidance:** The documentation should provide clear, step-by-step guidance on how to generate cryptographically secure seeds using appropriate methods available in Python (e.g., `secrets` module, `os.urandom`). Example code snippets demonstrating secure seed generation should be included.
    - **Code-level warning for default `PseudorandomSource`:** No explicit code-level warning or error is raised if default `PseudorandomSource` seed is used in key generation or encryption outside of test contexts.
    - **Secure default RNG or stronger encouragement:**  The default `PseudorandomSource` is not cryptographically secure. Consider using a secure default RNG or implement stronger mechanisms to encourage users to explicitly provide a secure RNG.
    - **Input validation and warnings**: The key generation functions could include checks or warnings if a potentially weak seed (e.g., within a certain range, or a default value) is used.
    - **Security focused documentation**: Create a dedicated security documentation section that emphasizes secure key generation practices, seed management, and potential risks of weak seeds.
    - **Security audit**:  A comprehensive security audit of the random number generation and usage throughout the library.

- **Preconditions:**
    1. **User behavior:** Developers directly copy the example key generation code from the `README.md` or similar insecure examples into their production applications, or use default `PseudorandomSource` without setting a secure seed.
    2. **Lack of secure seed replacement:** Developers fail to replace the placeholder `seed=1` or default seed with a cryptographically secure random seed.
    3. **Attacker knowledge:** An attacker gains knowledge of the seed value (which is trivial in case of `seed=1` or default seed) or the default seed behavior of `PseudorandomSource`.
    4. **Ciphertext access:** Attacker obtains ciphertext encrypted with keys derived from the weak or default seed.

- **Source Code Analysis:**
    - **File: `/code/README.md`**:
        - The "Quick start" example for `jaxite_bool` demonstrates key generation using `bool_params.get_lwe_rng_for_128_bit_security(seed=1)` and `bool_params.get_rlwe_rng_for_128_bit_security(seed=1)`.
        - The comment `# Note: In real applications, a cryptographically secure seed needs to be # used.` is present as a weak attempt to mitigate the risk, but is insufficient.
        - The example code encourages insecure practice by providing a direct, copy-pasteable code snippet with a known weak seed.
    - **File: `/code/jaxite/jaxite_lib/random_source.py`**:
        ```python
        class PseudorandomSource(RandomSource):
            """An insecure random source based on the Python stdlib."""

            def __init__(
                self,
                uniform_bounds: tuple[int, int] = (0, 2**32 - 1),
                normal_std: int = 1,
                seed: int = 1, # Default seed is 1
            ) -> None:
                self.uniform_bounds = uniform_bounds
                self.normal_std = normal_std
                self.rng = random.Random(seed) # Uses Python's standard random library
        ```
        - `PseudorandomSource` is initialized with a default `seed=1` if no seed is explicitly provided, making it predictable by default.
    - **Test Files**:
        - Test files like `/code/jaxite/jaxite_lib/rgsw_test.py`, `/code/jaxite/jaxite_bool/jaxite_bool_test.py` use `random_source.PseudorandomSource` with default seed or fixed seeds like `seed=1`, `seed=0`, or `seed=2` in test setups, demonstrating the usage of seeds and highlighting the risk if users apply similar insecure practices in production by copying test code snippets.

- **Security Test Case:**
    1. **Setup (Vulnerable Service):**
        - Deploy a vulnerable service using `jaxite_bool` for encryption. Configure the service to use the key generation code directly from the `README.md` example, including `seed=1`. Alternatively, configure it to use `PseudorandomSource` with default initialization (no seed provided).
        - Ensure the service encrypts some sensitive data using this setup.
    2. **Key Regeneration (Attacker):**
        - Obtain the source code or configuration of the vulnerable service to confirm the seed usage (or default seed usage).
        - Locally, use the Jaxite library to regenerate the encryption keys by using the same insecure seed (`seed=1`) or by using `PseudorandomSource` with default initialization. Use the same key generation functions as used in the vulnerable service (e.g., `bool_params.get_lwe_rng_for_128_bit_security(seed=1)` or `bool_params.get_lwe_rng_for_128_bit_security()`).
    3. **Ciphertext Acquisition (Attacker):**
        - Obtain a sample of ciphertext from the deployed vulnerable service. This could be through network interception, accessing logs or databases, or other means depending on the application.
    4. **Decryption (Attacker):**
        - Using the locally regenerated client key set and the decryption functions of Jaxite (`jaxite_bool.decrypt`), attempt to decrypt the ciphertext obtained from the deployed service.
    5. **Verification (Attacker):**
        - Successfully decrypt the ciphertext and recover the original sensitive plaintext. This confirms the vulnerability: predictable or default seed leads to compromised encryption, allowing unauthorized decryption by an attacker who can reproduce the keys.