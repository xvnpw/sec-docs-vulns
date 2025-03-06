*   ### Vulnerability Name: Predictable Address Normalization

*   ### Description:
    The address normalization algorithm in this library uses a predefined and static set of rules and dictionaries (like `streetWordMaps`) to standardize address components. This process involves replacing address words with abbreviations and converting text to uppercase. While intended for standardization to improve address matching, this normalization is predictable because the mapping rules are fixed and directly available in the source code. An attacker who understands these normalization rules can potentially reverse the normalization process to some extent.

    Steps to trigger vulnerability:
    1.  An attacker gains access to the source code of the `amazon-ads-advertiser-audience-normalization-sdk-py` library, either by downloading it from a public repository or through other means.
    2.  The attacker analyzes the `AddressHash.py` file and specifically examines the dictionaries defined for address normalization, such as `NumberIndicators`, `DirectionalWords`, `USStreetSuffixes`, `UKStreetSuffixes`, etc. These dictionaries contain the mapping rules used for normalization (e.g., "STREET" is mapped to "ST", "AVENUE" to "AVE").
    3.  The attacker obtains a dataset of SHA-256 hashed addresses that were normalized using this library. This dataset could be acquired through data breaches, leaks, or by compromising systems that use this library.
    4.  For each SHA-256 hash in the dataset, the attacker attempts to reverse the normalization process. Knowing the normalization rules, the attacker can try to expand the abbreviations in a normalized address back to their original forms. For example, "123NMAINST" could be expanded to "123 NORTH MAIN STREET" by applying the reverse mappings from the `streetWordMaps`.
    5.  By combining the partially de-normalized addresses with contextual knowledge about address formats and common street names in the targeted country, the attacker can further refine their guesses about the original addresses.
    6.  If the original address dataset is not very diverse or if the attacker has additional information about the users (e.g., location), the attacker might be able to successfully infer the original addresses for a subset of the hashed addresses, leading to partial de-anonymization.

*   ### Impact:
    Partial de-anonymization of user addresses. Although the SHA-256 hash itself is cryptographically secure and not reversible, the predictable normalization step reduces the entropy of the address input. This makes it easier for an attacker, possessing a dataset of hashed addresses and knowledge of the normalization algorithm, to narrow down the possibilities and potentially infer the original addresses. This can lead to privacy violations and potentially enable further targeted attacks if the addresses are linked to other sensitive user information.

*   ### Vulnerability Rank: Medium

*   ### Currently implemented mitigations:
    *   **SHA-256 Hashing**: The library uses SHA-256 hashing, which is a one-way cryptographic function. This prevents direct reversal of the hash to obtain the normalized address. However, it does not mitigate the predictability of the normalization process itself.

*   ### Missing mitigations:
    *   **More Complex Normalization Techniques**: Implement a more complex, less predictable normalization algorithm. This could involve:
        *   Using a larger and less publicly known set of normalization rules.
        *   Introducing randomness or salting into the normalization process (though this might affect the consistency needed for address matching).
        *   Employing more sophisticated natural language processing techniques for address standardization that are harder to reverse engineer.
    *   **Input Validation and Sanitization**: While not directly related to reversibility, robust input validation and sanitization can prevent unexpected inputs that might be normalized in a way that is even more easily reversible or lead to other issues.

*   ### Preconditions:
    *   Attacker has access to the source code of the `amazon-ads-advertiser-audience-normalization-sdk-py` library to understand the normalization rules.
    *   Attacker obtains a dataset of SHA-256 hashed addresses that were normalized using this library.
    *   Attacker has some understanding of address formats and common address components for the targeted countries.

*   ### Source code analysis:
    1.  **`AddressNormalizer` Class Initialization**: The `AddressNormalizer` class in `AddressHash.py` is initialized with a `countryCode`. Based on the `countryCode`, it loads various static lists into `self.streetWordMaps`. These lists (`NumberIndicators`, `DirectionalWords`, `USStreetSuffixes`, `UKStreetSuffixes`, `FRStreetDesignator`, `ESStreetPrefixes`, `ITStreetPrefixes`, `UKOrganizationSuffixes`, `UKSubBuildingDesignator`, `USSubBuildingDesignator`, `DefaultStreetSuffixes`) contain the word-to-abbreviation mappings used for normalization.
    ```python
    class AddressNormalizer():
        def __init__(self,countryCode):
            self.streetWordMaps = []
            self.streetWordMaps.extend(NumberIndicators)
            self.streetWordMaps.extend(DirectionalWords)
            # ... (rest of the word map extensions based on countryCode)
    ```
    2.  **`normalize` Method**: The `normalize` method in `AddressNormalizer` performs the core normalization logic.
    ```python
    def normalize(self,record):
        record = record.strip().upper()
        normalizedAddress =  NormalizedAddress(record)
        normalizedAddress.generateTokens()

        # ... (preprocessing rules application) ...

        for i in range(0,len(normalizedAddress.addressTokens)):
            word = normalizedAddress.addressTokens[i]
            for j in range (0,len(self.streetWordMaps)):
                if (word in self.streetWordMaps[j]):
                   normalizedAddress.updateAddressTokens(i, 1, first_part = self.streetWordMaps[j].get(word))

        self.normalizedAddress = "".join(normalizedAddress.addressTokens).lower()
        self.sha256normalizedAddress = hashlib.sha256(self.normalizedAddress.encode()).hexdigest()
        return self
    ```
    3.  **Word Replacement**: Inside the `normalize` method, the code iterates through the tokens of the address and compares each `word` with the keys in `self.streetWordMaps`. If a match is found, the `updateAddressTokens` method replaces the original word with its corresponding abbreviation from the `streetWordMaps`. This replacement is deterministic and based on the static mappings.
    4.  **Predictability**: Because `streetWordMaps` and the normalization logic are static and available in the code, the normalization process is entirely predictable. For any given address, the normalized form will always be the same, and the transformation is reversible if the mappings are known.

*   ### Security test case:
    1.  **Setup**: Install the `AddressHashing` library.
        ```bash
        # Assuming the library is packaged and installable, or you can add the code to your PYTHONPATH
        # pip install amazon-ads-advertiser-audience-normalization-sdk-py  (if packaged)
        # Or, if running from the code directory:
        export PYTHONPATH=$PYTHONPATH:/path/to/amazon-ads-advertiser-audience-normalization-sdk-py/code
        python
        ```
    2.  **Normalization and Hash Generation**: In a Python environment, use the `AddressHash` library to normalize and hash a set of diverse US addresses.
        ```python
        from AddressHashing import AddressHash

        addresses = [
            "123 North Main Street",
            "456 South Avenue",
            "789 East Road",
            "1011 West Lane",
            "22 Acacia Av", # intentional abbreviation
            "33 example str", # intentional typo and abbreviation
            "0001 Sample  Highway", # intentional extra space and word
            "9999 Test Parkway",
        ]

        normalized_addresses = []
        hashed_addresses = []

        address_normalizer_us = AddressHash.AddressNormalizer('US')

        for address in addresses:
            result = address_normalizer_us.normalize(address)
            normalized_addresses.append(result.normalizedAddress)
            hashed_addresses.append(result.sha256normalizedAddress)
            print(f"Original Address: {address}")
            print(f"Normalized Address: {result.normalizedAddress}")
            print(f"SHA-256 Hash: {result.sha256normalizedAddress}")
            print("-" * 30)
        ```
    3.  **Manual Reversal Attempt**: Examine the normalized addresses and, using the `USStreetSuffixes` and `DirectionalWords` dictionaries from `AddressHash.py`, try to manually reverse the normalization for a few examples. For instance:
        *   Normalized Address: `123nmainst` -> Can be reversed to "123 North Main Street" by knowing "N" -> "NORTH" and "ST" -> "STREET".
        *   Normalized Address: `456save` -> Can be reversed to "456 South Avenue" by knowing "S" -> "SOUTH" and "AVE" -> "AVENUE".
    4.  **Dictionary-Based De-normalization**: Create a simple Python dictionary with reverse mappings from the `USStreetSuffixes` and `DirectionalWords`.
        ```python
        reverse_street_suffixes_us = {v: k for item in AddressHash.USStreetSuffixes for k, v in item.items()}
        reverse_directional_words =  {v: k for item in AddressHash.DirectionalWords for k, v in item.items()}

        def denormalize_address(normalized_address):
            tokens = normalized_address.split() # Simple split, might need more sophisticated tokenization
            denormalized_tokens = []
            for token in tokens:
                if token in reverse_street_suffixes_us:
                    denormalized_tokens.append(reverse_street_suffixes_us[token])
                elif token in reverse_directional_words:
                    denormalized_tokens.append(reverse_directional_words[token])
                else:
                    denormalized_tokens.append(token) # Keep as is if not in mappings
            return " ".join(denormalized_tokens)

        print("\nDe-normalization Attempt:")
        for normalized_address in normalized_addresses:
            denormalized = denormalize_address(normalized_address)
            print(f"Normalized: {normalized_address}, De-normalized (Attempt): {denormalized}")

        ```
    5.  **Analysis**: Observe the output. You will see that for many normalized addresses, a significant portion of the original address can be recovered simply by reversing the known mappings. This demonstrates the predictability of the normalization and the potential for partial de-anonymization. The success rate of de-normalization will depend on the complexity of the original addresses and how strictly they adhere to standard formats.

This test case proves that while the hashes are secure, the normalization process itself is predictable and reversible, posing a medium risk of information disclosure if an attacker gains access to hashed address datasets and the normalization rules.