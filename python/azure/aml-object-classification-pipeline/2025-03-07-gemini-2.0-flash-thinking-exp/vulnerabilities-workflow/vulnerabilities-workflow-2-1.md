- Vulnerability Name: Model Vulnerability to Adversarial Examples
- Description:
    - The deployed object classification model is vulnerable to adversarial examples.
    - An attacker can craft specifically perturbed images (adversarial examples) that are visually indistinguishable from benign images to humans but cause the model to misclassify them.
    - Step-by-step trigger:
        1. An attacker analyzes the deployed model (black-box or white-box access depending on the scenario, black-box is assumed for external attacker).
        2. The attacker crafts an adversarial example image designed to be misclassified as a target class (e.g., crafting an image of a car to be classified as an airplane).
        3. The attacker encodes the adversarial example image to base64.
        4. The attacker sends a POST request to the webservice endpoint (`scoring_url`) with a JSON payload containing the base64 encoded adversarial image in the `data` field.
        5. The webservice processes the image and the model misclassifies the adversarial example as the target class specified by the attacker during the adversarial crafting process.
- Impact:
    - Misclassification of objects.
    - Undermining the intended functionality of the object classification system.
    - In scenarios where the object classification is used for critical decision-making, adversarial attacks could lead to incorrect or manipulated outcomes. For example, in an autonomous driving context, misclassifying a stop sign as something else could have severe consequences.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - None. The project does not implement any adversarial robustness techniques.
- Missing Mitigations:
    - Adversarial training: Train the model on adversarial examples to improve its robustness.
    - Input validation and sanitization: While basic preprocessing is done (resizing, cropping, normalization), no specific adversarial input detection or filtering is implemented.
    - Rate limiting on the webservice endpoint to mitigate automated adversarial attacks.
    - Output probability thresholding: Reject predictions with low confidence scores, as adversarial examples often lead to lower confidence predictions.
    - Implement input perturbation detection mechanisms to identify and flag potentially adversarial inputs.
- Preconditions:
    - The object classification webservice must be deployed and accessible to the attacker (publicly accessible in this demo scenario).
    - The attacker needs to be able to craft or obtain adversarial examples effective against the RESNET-18 architecture or similar models. This is a well-researched area, and crafting effective adversarial examples is feasible.
- Source Code Analysis:
    - `modules/deploy/score.py`: This script handles the model inference. It takes base64 encoded image data as input, preprocesses it, and feeds it to the loaded PyTorch model.
    - The `preprocess_image` function in `modules/deploy/score.py` performs standard image preprocessing (resize, center crop, normalize) but does not include any adversarial input detection or mitigation.
    - The `run` function in `modules/deploy/score.py` directly uses the preprocessed image for inference without any checks for adversarial perturbations.
    - The training process in `modules/train/*` does not include any adversarial training techniques. The model is trained only on benign images obtained from Bing Image Search API.
    - Visualization:
        ```
        [External Attacker] --> [test-endpoint.py / crafted request] --> [Webservice Endpoint (score.py)] --> [RESNET-18 Model] --> Misclassification due to Adversarial Example
        ```
- Security Test Case:
    - Step 1: Deploy the Azure ML pipeline and obtain the `scoring_url` from the deployment step output.
    - Step 2: Obtain or craft an adversarial example image. For example, use a pre-generated adversarial example against RESNET-18 or use libraries like Foolbox, CleverHans, or ART to generate one. A simple example could be adding small perturbations to an image of a 'car' to make it misclassified as 'airplane'.
    - Step 3: Encode the adversarial example image to base64.
    - Step 4: Create a JSON payload: `{"data": "BASE64_ENCODED_ADVERSARIAL_IMAGE"}`.
    - Step 5: Send a POST request to the `scoring_url` with the JSON payload and `Content-Type: application/json` header using `curl`, `requests` library in Python, or similar tools.
        ```bash
        curl -X POST -H "Content-Type: application/json" -d '{"data": "BASE64_ENCODED_ADVERSARIAL_IMAGE"}' <scoring_url>
        ```
    - Step 6: Analyze the JSON response. Verify that the `label` in the response is an incorrect classification (the target class of the adversarial attack) despite the image visually resembling a different class to a human observer.
    - Expected Result: The model misclassifies the adversarial example, demonstrating the vulnerability. For instance, an image of a car, imperceptibly perturbed, is classified as 'airplane' with high probability.