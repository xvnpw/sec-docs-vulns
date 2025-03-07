- Vulnerability name: **Potential Bias in Pseudorandom Number Generation due to Predictable Seed**
- Description:
    1. The code uses `random_source.PseudorandomSource` as a default random number generator in several test cases (e.g., `rgsw_test.py`, `blind_rotate_test.py`, `key_switch_test.py`, `lwe_test.py`, `bootstrap_test.py`).
    2. `PseudorandomSource` is initialized with a default `seed=1` if no seed is explicitly provided.
    3. In test scenarios, especially in parameterized tests, consistent and predictable seeds are used for reproducibility, but sometimes these are not overridden, or easily overridable by users if they were to copy test code for real world use.
    4. If a user copies code snippets from the README or test files and uses them in a production environment without changing the seed, the cryptographic operations will rely on a predictable seed.
    5. An attacker knowing that the default seed is used could potentially predict the generated random numbers, compromising the security of the homomorphic encryption scheme.
- Impact:
    - **High**: If the predictable seed is used in key generation or encryption in a real-world application, an attacker could potentially predict the secret keys or the randomness used for encryption. This could lead to decryption of ciphertexts without authorization or manipulation of encrypted computations.
- Vulnerability rank: **High**
- Currently implemented mitigations:
    - The README and code examples mention that "In real applications, a cryptographically secure seed needs to be used." This is a form of documentation-based mitigation.
    - The code allows users to provide their own `RandomSource` implementations and seeds, offering flexibility to use cryptographically secure RNGs.
- Missing mitigations:
    - **Code-level warning**: No explicit code-level warning or error is raised if default seed is used in key generation or encryption outside of test contexts.
    - **Secure default RNG**: The default `PseudorandomSource` is not cryptographically secure. A secure default RNG should be used, or users should be strongly encouraged to explicitly provide a secure RNG.
    - **Security audit**:  A comprehensive security audit of the random number generation and usage throughout the library.
- Preconditions:
    1. The attacker must know or suspect that the Jaxite library is being used.
    2. The attacker must be aware that the user might have used default or predictable seeds, potentially by copying code directly from examples or tests without proper security considerations.
- Source code analysis:
    - File: `/code/jaxite/jaxite_lib/random_source.py`
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
    - Many test files use `random_source.PseudorandomSource` without explicitly setting a cryptographically secure seed. For example in `/code/jaxite/jaxite_lib/rgsw_test.py`:
    ```python
    self.noise_free_rng = random_source.CycleRng(const_normal_noise=0) # CycleRng for no noise tests
    self.default_key = rgsw.gen_key(
        params=parameters.SchemeParameters(
            # ...
        ),
        prg=self.noise_free_rng, # noise_free_rng is CycleRng, not PseudorandomSource in this setup, but other tests use PseudorandomSource
    )
    ```
    - In `/code/jaxite/jaxite_bool/bool_params.py`, for 128-bit security, `PseudorandomSource` is used, but seeds are provided as arguments to `get_lwe_rng_for_128_bit_security` and `get_rlwe_rng_for_128_bit_security`, encouraging better practice in security-critical contexts, but not preventing insecure default usage elsewhere.

- Security test case:
    1. **Setup**: Create two `ClientKeySet` instances, one using the default `PseudorandomSource` and another using a cryptographically secure RNG (e.g., `SystemRandomSource`).
    2. **Key Generation**: Generate client and server keys for both instances.
    3. **Encryption**: Encrypt the same boolean value (e.g., `True`) using both client key sets.
    4. **Key Prediction (Conceptual)**: In a real attack, the attacker would attempt to predict the key. In this test case, we will demonstrate the predictability by showing that with the default seed, the key generation becomes deterministic. For simplicity in this test, we can compare the keys directly instead of simulating full key prediction.
    5. **Comparison**: Compare the generated secret keys from both instances. The keys from the default `PseudorandomSource` should be identical across multiple runs if initialized the same way (or very predictably related), demonstrating the lack of cryptographic security. The keys from the secure RNG should be different in each run.
    6. **Decryption (Conceptual)**: Show that if an attacker somehow obtained the predictable key (due to default seed), they could decrypt ciphertexts encrypted with keys derived from the same default seed.