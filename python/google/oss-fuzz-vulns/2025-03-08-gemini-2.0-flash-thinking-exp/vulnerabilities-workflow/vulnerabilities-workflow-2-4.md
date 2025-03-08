- vulnerability name: Data Injection/Modification via Malicious Pull Requests
- description: An attacker could submit a malicious pull request to the repository that injects or modifies vulnerability data. If merged, this pull request would introduce incorrect or misleading vulnerability information into the OSS-Fuzz vulnerabilities database. This could be achieved by altering YAML files, which are the primary data storage format in this repository, to contain false vulnerability details, such as incorrect affected versions, commit ranges, or vulnerability descriptions. The repository's purpose is to serve as a source of truth for vulnerability data in JSON/YAML format, making it a target for attackers seeking to manipulate this data.
- impact: Downstream consumers of the OSS-Fuzz vulnerabilities data, such as OSV, rely on this repository as the source of truth. Incorrect or misleading vulnerability information can have several negative impacts:
    - **False Negatives:**  Incorrectly marking a vulnerability as fixed or not affecting certain versions could lead users to believe they are not vulnerable when they are, resulting in unpatched systems.
    - **False Positives:** Injecting false vulnerabilities could cause unnecessary alarm and workload for users, leading them to investigate non-existent issues.
    - **Data Integrity Compromise:** The repository's integrity as a reliable source of vulnerability information is undermined.
- vulnerability rank: Medium
- currently implemented mitigations:
    - Code reviews are mandatory for all pull requests, including those from project members. This process is mentioned in `CONTRIBUTING.md` and enforced by the project's contribution workflow.
- missing mitigations:
    - Automated validation of vulnerability data in pull requests before merging is missing. This should include:
        - Schema validation to ensure the submitted YAML/JSON files adhere to the defined format spec (e.g., OSV schema).
        - Consistency checks to verify the logical coherence of the vulnerability data (e.g., fixed version is after introduced version).
        - Sanity checks to detect obviously incorrect or nonsensical vulnerability information.
    - Stronger access controls for merging pull requests. Restricting merge permissions to a smaller, trusted group of project maintainers could reduce the risk of malicious merges.
    - Implement auditing and monitoring of changes to vulnerability files in the repository to quickly detect and revert any malicious modifications.
- preconditions:
    - The attacker has a GitHub account and the ability to create a pull request to the `OSS-Fuzz-vulns` repository, which is publicly accessible.
    - A project member with merge permissions inadvertently or maliciously merges the attacker's pull request.
- source code analysis:
    - The provided files, such as `OSV-2024-198.yaml`, `OSV-2025-74.yaml` and others under `/code/vulns/libxml2/`, `/code/vulns/gpac/`, `/code/vulns/wasm3/`, `/code/vulns/mruby/`, `/code/vulns/jsign/`, `/code/vulns/antlr4-java/`, `/code/vulns/libcoap/`, `/code/vulns/p11-kit/`, `/code/vulns/assimp/`, and `/code/vulns/ndpi/`, are examples of vulnerability data stored as YAML files. These files are intended to document real-world vulnerabilities discovered by OSS-Fuzz.
    - The vulnerability stems from the project's workflow, which relies on manual code reviews for data integrity. While code reviews are a valuable security practice, they are not foolproof and can be susceptible to human error or oversight, especially when dealing with a large volume of contributions.
    - The `README.md` file indicates that user contributions are encouraged ("Users may submit PRs to update any information here.") and automatically processed by OSV ("Any user changes to vulnerability files in this repository will trigger a re-analysis by OSV within a few minutes"). This design, while promoting community contributions, increases the attack surface and highlights the need for robust automated validation to prevent malicious data injection.
- security test case:
    1. **Attacker Action:** Create a GitHub account (if they don't already have one).
    2. **Attacker Action:** Fork the `OSS-Fuzz-vulns` repository.
    3. **Attacker Action:** Create a new branch in their forked repository.
    4. **Attacker Action:** Choose an existing vulnerability YAML file (e.g., any of the files provided in PROJECT FILES such as `/code/vulns/h3/OSV-2022-880.yaml` or `/code/vulns/ndpi/OSV-2022-670.yaml`) and modify it in a way that introduces incorrect information. For example, change the `fixed` commit to an earlier commit than the `introduced` commit, or alter the vulnerability `details` to be misleading or false.
    5. **Attacker Action:** Submit a pull request to the upstream `OSS-Fuzz-vulns` repository with these malicious changes.
    6. **Vulnerability Verification:** If the pull request is merged by a project member without detecting the malicious changes (due to lack of scrutiny or automated validation), the vulnerability is considered successfully injected.
    7. **Downstream Impact (Verification, outside of this test case):** Verify that OSV or other downstream consumers now reflect the incorrect vulnerability information. For example, query the OSV API for the vulnerability and check if the affected ranges or details are now incorrect as modified in the malicious PR.