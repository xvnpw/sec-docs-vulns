- Vulnerability Name: Side-Channel Attack Framework
- Description: The SCAAML project provides a framework and tutorials for performing side-channel attacks, specifically targeting cryptographic implementations. An attacker can use this framework and the provided resources to learn and execute side-channel attacks against vulnerable hardware or software implementations of cryptographic algorithms like AES and ECC. By following the tutorials and using the framework, an attacker can analyze power consumption traces and other side-channel leakage to extract secret keys.
- Impact: Successful side-channel attacks can lead to the extraction of sensitive cryptographic keys. This can compromise the confidentiality and security of systems relying on the targeted cryptographic implementations.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - Disclaimer: The `README.md` and `scaaml_intro/README.md` files contain disclaimers stating that SCAAML is not an official Google product and is for educational and demo purposes only. The `scaaml_intro` tutorial is explicitly marked as "for educational and demo purpose only. It is not suitable for research as TinyAES is an easy target".
- Missing Mitigations: None (by design, the project is intended to facilitate side-channel attacks for research and education). It's not about mitigating the vulnerability in SCAAML itself, but about making users aware of the risks when using SCAAML against real-world systems.
- Preconditions: An attacker needs access to a vulnerable cryptographic implementation and the SCAAML framework (which is publicly available).
- Source Code Analysis:
    - The entire repository code is designed to facilitate side-channel attacks.
    - The `/scaaml/` directory contains the core SCAAML framework code.
    - The `/scaaml_intro/` directory provides tutorials and examples on how to use the framework to perform AES side-channel attacks.
    - The `/papers/2024/GPAM/` directory contains code and datasets related to advanced side-channel attack models (GPAM).
    - The code is written in Python and uses TensorFlow for deep learning based attacks.
    - The tutorials and examples are designed to guide a user through the process of performing side-channel attacks, including data capture, preprocessing, model training, and key recovery.
- Security Test Case:
    1. Set up the SCAAML framework as described in the `README.md`.
    2. Follow the `scaaml_intro` tutorial to perform an AES side-channel attack.
    3. Download the provided dataset (`datasets.zip`) and models (`models.zip`) for the TinyAES tutorial from `scaaml_intro/README.md`.
    4. Run the `key_recovery_demo.ipynb` notebook in the `scaaml_intro` directory, using either the provided pre-trained models or train new models using `train.py` and `config/stm32f415_tinyaes.json`.
    5. Observe if the attacker can successfully recover the TinyAES key with a small number of traces as demonstrated in the tutorial, verifying the framework's capability to facilitate side-channel attacks.