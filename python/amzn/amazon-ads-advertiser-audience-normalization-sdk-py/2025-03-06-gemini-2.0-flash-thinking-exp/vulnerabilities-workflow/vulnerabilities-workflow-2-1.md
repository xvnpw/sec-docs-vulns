### Vulnerability List

- **Vulnerability Name:** Inconsistent Normalization due to Incomplete Street Name Mappings

- **Description:**
    1. The `AddressNormalizer` class utilizes predefined dictionaries (`streetWordMaps`) to standardize address components, such as street suffixes (e.g., "Street" to "ST", "Avenue" to "AVE") and directional words (e.g., "North" to "N").
    2. These `streetWordMaps` might be incomplete and may not encompass all possible variations, abbreviations, or misspellings of street names used in real-world addresses.
    3. When an input address contains a street name component that is not present in the `streetWordMaps`, the normalization process fails to standardize that specific component.
    4. This can lead to inconsistent normalized addresses and consequently, different hash values for addresses that are semantically identical but syntactically slightly different due to the unmapped variations.
    5. An attacker could exploit this by crafting addresses with unmapped street name variations. When these addresses are used for data matching in Amazon's advertising platforms, the subtly different hashes might result in missed matches or unintended data leakage if different variations are treated as distinct entities in downstream processes.

- **Impact:**
    - Inconsistent data matching in Amazon Marketing Cloud and Amazon DSP.
    - Reduced match rates for address data uploaded to Amazon advertising platforms.
    - Potential for inaccurate audience targeting due to inconsistent address normalization.
    - In specific scenarios, subtle data manipulation could lead to unintended data leakage if variations in address normalization are treated differently in downstream processes.

- **Vulnerability Rank:** Medium

- **Currently Implemented Mitigations:**
    - None. The code relies on static `streetWordMaps` that may not be exhaustive and are not automatically updated or extended to cover new variations.

- **Missing Mitigations:**
    - **Comprehensive Street Word Mappings:** Expand the `streetWordMaps` to include a more comprehensive list of street name variations, abbreviations, synonyms, and common misspellings for each supported country. This could involve using external and regularly updated address dictionaries or gazetteer data.
    - **Fuzzy Matching or Levenshtein Distance:** Implement fuzzy matching algorithms or Levenshtein distance calculations to identify and normalize street names that are similar but not exact matches to the entries in `streetWordMaps`. This would allow the system to handle minor typos and slight variations in street names more gracefully.
    - **Logging and Monitoring of Unmapped Words:** Implement logging to track instances where address components are not normalized due to missing mappings in `streetWordMaps`. This would provide insights into gaps in the current mappings and help prioritize updates to improve coverage and consistency.

- **Preconditions:**
    - The attacker needs to identify or guess street name variations, abbreviations, or misspellings that are not included in the library's `streetWordMaps` for the target country.
    - The attacker must be able to input addresses into a system that uses this library for normalization and hashing before data matching in Amazon advertising platforms. This could be through a web form, API, or data upload process that utilizes this library.

- **Source Code Analysis:**
    1. **`AddressNormalizer.normalize(self, record)`:** This method is the primary function responsible for address normalization. It takes an address string as input (`record`).
    2. **`normalizedAddress = NormalizedAddress(record)`:** An instance of `NormalizedAddress` is created to hold the address and its tokens.
    3. **`normalizedAddress.generateTokens()`:** The input address string is tokenized into individual words or components based on delimiters defined in the `Delimiter` class.
    4. **`for i in range (0,len(a)): rule = a[i]; rule.apply(normalizedAddress)`:** Preprocessing rules (like `Dash` and `Pound`) are applied to further refine the tokens.
    5. **`for i in range(0,len(normalizedAddress.addressTokens)): word = normalizedAddress.addressTokens[i]; for j in range (0,len(self.streetWordMaps)): if (word in self.streetWordMaps[j]): normalizedAddress.updateAddressTokens(i, 1, first_part = self.streetWordMaps[j].get(word))`:** This nested loop is where the vulnerability lies. It iterates through each token in the `normalizedAddress.addressTokens` list. For each `word` (token), it then iterates through the list of dictionaries `self.streetWordMaps`.
        - **Vulnerability Point:** Inside the inner loop, it checks `if (word in self.streetWordMaps[j])`. This condition checks if the current `word` exactly matches a key in any of the dictionaries within `streetWordMaps`. If a match is found, `normalizedAddress.updateAddressTokens` is called to replace the original token with its standardized form (the value associated with the key in the dictionary). However, if a token (street name component) is *not* found as a key in any dictionary in `streetWordMaps`, the `if` condition is false, and the code proceeds without normalizing that specific token. This unnormalized token is then used in the final normalized address string and subsequently hashed.
    6. **`self.normalizedAddress = "".join(normalizedAddress.addressTokens).lower()`:** The tokens (some normalized, some potentially not) are joined back into a single string to form `self.normalizedAddress`, which is then converted to lowercase.
    7. **`self.sha256normalizedAddress = hashlib.sha256(self.normalizedAddress.encode()).hexdigest()`:** Finally, the `self.normalizedAddress` is hashed using SHA-256, and the resulting hash is stored in `self.sha256normalizedAddress`. Because of the potential for unnormalized components, semantically similar addresses can result in different `normalizedAddress` strings and different `sha256normalizedAddress` hashes if they contain street name variations not present in `streetWordMaps`.

- **Security Test Case:**
    1. **Setup:** Prepare a Python environment where the `AddressHashing` library is installed.
    2. **Choose Country Code:** Select "US" as the country code for the `AddressNormalizer`.
    3. **Identify Unmapped Variation:**  Note that "Parkways" is mapped to "PKWY" in `USStreetSuffixes`, but "Park Way" (two words) is not explicitly mapped.
    4. **Craft Test Addresses:** Create two address strings:
        - `address1 = '123 Main Parkways Street'` (Uses mapped "Parkways")
        - `address2 = '123 Main Park Way Street'` (Uses unmapped "Park Way")
    5. **Normalize Addresses:** Instantiate `AddressNormalizer` for "US" and normalize both addresses:
        ```python
        from AddressHashing import AddressHash

        address_normalizer_us = AddressHash.AddressNormalizer('US')

        result1 = address_normalizer_us.normalize(address1)
        normalized_address1 = result1.normalizedAddress
        hashed_address1 = result1.sha256normalizedAddress

        result2 = address_normalizer_us.normalize(address2)
        normalized_address2 = result2.normalizedAddress
        hashed_address2 = result2.sha256normalizedAddress
        ```
    6. **Analyze Results:** Print and compare the `normalized_address1`, `hashed_address1`, `normalized_address2`, and `hashed_address2`.
        ```python
        print(f"Address 1:")
        print(f"  Normalized: {normalized_address1}")
        print(f"  Hashed:     {hashed_address1}")
        print(f"\nAddress 2:")
        print(f"  Normalized: {normalized_address2}")
        print(f"  Hashed:     {hashed_address2}")
        ```
    7. **Expected Output and Validation:**
        - `normalized_address1` should be: `"123mainpkwystreet"` (or similar, with "Parkways" normalized to "PKWY").
        - `hashed_address1` will be a SHA256 hash of `normalized_address1`.
        - `normalized_address2` should be: `"123mainpark waystreet"` (or similar, with "Park Way" remaining as is, unnormalized).
        - `hashed_address2` will be a SHA256 hash of `normalized_address2`.
        - **Crucially, `hashed_address1` and `hashed_address2` should be different**, demonstrating that the addresses, though semantically very similar, produce different hashes due to the incomplete street name mappings. This difference in hashes confirms the vulnerability, as it shows inconsistent normalization.

This test case demonstrates how subtle variations in street names, if not comprehensively mapped, can lead to inconsistent normalization and different hash outputs, which can be exploited to cause issues in data matching within Amazon's advertising platforms.