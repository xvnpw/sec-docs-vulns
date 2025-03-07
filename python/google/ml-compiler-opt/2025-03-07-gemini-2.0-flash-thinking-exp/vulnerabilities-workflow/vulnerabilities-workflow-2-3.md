- Vulnerability name: Malicious Pre-trained Model Distribution
- Description:
  - An attacker could compromise the pre-trained model release process on the ml-compiler-opt GitHub repository.
  - By gaining control over the release mechanism, the attacker can upload a malicious pre-trained model, disguised as a legitimate release.
  - Unsuspecting users, when configuring LLVM with the `-DLLVM_INLINER_MODEL_PATH=download` option, will automatically download this malicious model during the CMake configuration process.
  - This happens because CMake is configured to fetch the "most recent compatible model from github" without any integrity checks.
  - Subsequently, when users compile software using this compromised LLVM build, the malicious model could be used to guide compiler optimizations, potentially introducing subtle vulnerabilities or backdoors into the compiled software.
- Impact:
  - **Critical**. Successful exploitation of this vulnerability could lead to the distribution of malicious pre-trained models to a wide range of LLVM users.
  - This could result in widespread introduction of subtle vulnerabilities or backdoors in software compiled using LLVM with the compromised model.
  - The impact is severe as it directly undermines the security of software compiled using LLVM, potentially affecting numerous downstream users and systems.
- Vulnerability rank: critical
- Currently implemented mitigations:
  - **Semantic Versioning**: The project uses semantic versioning for model releases. Major version bumps indicate breaking changes on the LLVM/compiler side, which could signal to advanced users to be cautious when updating to a new major version, but it does not prevent the distribution of malicious models within a compatible version range or for new installations. This mitigation is described in `/code/README.md` under the "Pretrained models" section.
- Missing mitigations:
  - **Integrity Checks**: Missing integrity checks for pre-trained models. The project should implement a mechanism to ensure the integrity and authenticity of the downloaded models. This could be achieved through:
    - **Checksums**: Providing checksums (e.g., SHA256) for each released model, allowing users to verify the downloaded model's integrity manually.
    - **Digital Signatures**: Digitally signing model releases, enabling automated verification of the model's authenticity and integrity during download.
  - **Secure Download Channel**: While HTTPS is likely used for GitHub downloads, it is not explicitly stated as a security measure in the project documentation. Explicitly enforcing and documenting HTTPS for model downloads is crucial to prevent man-in-the-middle attacks during the download process.
- Preconditions:
  - **Compromised Release Process**: An attacker must successfully compromise the release process of the ml-compiler-opt GitHub repository. This could involve compromising maintainer accounts with release permissions or gaining unauthorized access to the release pipeline.
  - **`-DLLVM_INLINER_MODEL_PATH=download` Option**: Users must configure LLVM using the `-DLLVM_INLINER_MODEL_PATH=download` CMake option, triggering the automatic model download from GitHub.
- Source code analysis:
  - **File: `/code/README.md`**:
    - The section "Pretrained models" in `README.md` describes the `-DLLVM_INLINER_MODEL_PATH` flag and the `download` option:
      ```markdown
      When building LLVM, there is a flag `-DLLVM_INLINER_MODEL_PATH` which you may
      set to the path to your inlining model. If the path is set to `download`, then
      cmake will download the most recent (compatible) model from github to use.
      ```
    - This documentation confirms the existence of the vulnerable download functionality and highlights the automatic download behavior without any mention of security measures like integrity checks or secure download channels.
    - The description of model releases as "github releases" further emphasizes the reliance on the GitHub release process, which becomes the target of the described attack vector.
- Security test case:
  - **Setup**:
    - **Compromised Release Simulation**: In a test environment, simulate a compromise of the `ml-compiler-opt` GitHub repository's release process. This can be done by setting up a local mock GitHub repository or manipulating network traffic to redirect model download requests.
    - **Malicious Model Creation**: Create a malicious pre-trained model. This model should be designed to introduce a detectable vulnerability or backdoor during compilation, for example, by subtly altering code generation in a way that leads to a buffer overflow or an authentication bypass in compiled binaries.
    - **LLVM Configuration**: Prepare a test LLVM build environment configured to use the `-DLLVM_INLINER_MODEL_PATH=download` option.
  - **Steps**:
    1. **Trigger Malicious Download**: Configure and build LLVM in the test environment with `-DLLVM_INLINER_MODEL_PATH=download`. The CMake process should download the attacker's malicious model from the simulated compromised repository.
    2. **Compile Target Software**: Compile a simple, representative software project using the newly built, compromised LLVM. This software project should be designed to highlight the intended vulnerability or backdoor if the malicious model is effective.
    3. **Security Analysis**: Perform security analysis on the compiled software. This can include:
       - **Static Analysis**: Use static analysis tools to scan the compiled code for potential vulnerabilities introduced by the malicious model.
       - **Dynamic Analysis**: Run the compiled software and use dynamic analysis techniques (e.g., fuzzing, memory error detection) to identify runtime vulnerabilities.
       - **Manual Code Review**: Conduct a manual code review of the compiled software, specifically focusing on areas that the malicious model might have influenced, looking for backdoors or unexpected code patterns.
  - **Expected Outcome**:
    - The software compiled using the compromised LLVM exhibits the intended vulnerability or backdoor.
    - Security analysis tools and manual code review detect the introduced vulnerability or backdoor in the compiled software.
    - Benchmarking or testing demonstrates a functional difference or security regression in software compiled with the malicious model compared to software compiled with a legitimate model.
  - **Success Condition**:
    - The test is considered successful if it demonstrates that the software compiled with the malicious model contains exploitable vulnerabilities or backdoors, while software compiled with a legitimate model (or without the MLGO model) does not, thus validating the "Malicious Pre-trained Model Distribution" vulnerability.