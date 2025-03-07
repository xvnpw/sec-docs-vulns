## Combined Vulnerability List

### Vulnerability 1: Model Vulnerability to Adversarial Examples

- **Description:**
    - The deployed object classification model is vulnerable to adversarial examples.
    - An attacker can craft specifically perturbed images (adversarial examples) that are visually indistinguishable from benign images to humans but cause the model to misclassify them.
    - Step-by-step trigger:
        1. An attacker analyzes the deployed model (black-box or white-box access depending on the scenario, black-box is assumed for external attacker).
        2. The attacker crafts an adversarial example image designed to be misclassified as a target class (e.g., crafting an image of a car to be classified as an airplane).
        3. The attacker encodes the adversarial example image to base64.
        4. The attacker sends a POST request to the webservice endpoint (`scoring_url`) with a JSON payload containing the base64 encoded adversarial image in the `data` field.
        5. The webservice processes the image and the model misclassifies the adversarial example as the target class specified by the attacker during the adversarial crafting process.
- **Impact:**
    - Misclassification of objects.
    - Undermining the intended functionality of the object classification system.
    - In scenarios where the object classification is used for critical decision-making, adversarial attacks could lead to incorrect or manipulated outcomes. For example, in an autonomous driving context, misclassifying a stop sign as something else could have severe consequences.
- **Vulnerability Rank:** High
- **Currently Implemented Mitigations:**
    - None. The project does not implement any adversarial robustness techniques.
- **Missing Mitigations:**
    - Adversarial training: Train the model on adversarial examples to improve its robustness.
    - Input validation and sanitization: While basic preprocessing is done (resizing, cropping, normalization), no specific adversarial input detection or filtering is implemented.
    - Rate limiting on the webservice endpoint to mitigate automated adversarial attacks.
    - Output probability thresholding: Reject predictions with low confidence scores, as adversarial examples often lead to lower confidence predictions.
    - Implement input perturbation detection mechanisms to identify and flag potentially adversarial inputs.
- **Preconditions:**
    - The object classification webservice must be deployed and accessible to the attacker (publicly accessible in this demo scenario).
    - The attacker needs to be able to craft or obtain adversarial examples effective against the RESNET-18 architecture or similar models. This is a well-researched area, and crafting effective adversarial examples is feasible.
- **Source Code Analysis:**
    - `modules/deploy/score.py`: This script handles the model inference. It takes base64 encoded image data as input, preprocesses it, and feeds it to the loaded PyTorch model.
    - The `preprocess_image` function in `modules/deploy/score.py` performs standard image preprocessing (resize, center crop, normalize) but does not include any adversarial input detection or mitigation.
    - The `run` function in `modules/deploy/score.py` directly uses the preprocessed image for inference without any checks for adversarial perturbations.
    - The training process in `modules/train/*` does not include any adversarial training techniques. The model is trained only on benign images obtained from Bing Image Search API.
    - Visualization:
        ```
        [External Attacker] --> [test-endpoint.py / crafted request] --> [Webservice Endpoint (score.py)] --> [RESNET-18 Model] --> Misclassification due to Adversarial Example
        ```
- **Security Test Case:**
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

### Vulnerability 2: Model Poisoning via Bing Image Search Manipulation / Unvalidated Image Download from Bing Image Search (Data Poisoning)

- **Description:**
    - Step 1: The `data_ingestion.py` script is designed to automatically build a training dataset by fetching images from Bing Image Search based on a predefined list of class names (e.g., airplane, automobile, bird, etc.).
    - Step 2: An attacker identifies the class names used by the script and manipulates Bing Image Search results for these terms. This manipulation can be achieved through various techniques such as Search Engine Optimization (SEO) poisoning, compromising websites that are indexed by Bing, or other methods to influence search engine rankings and image associations.
    - Step 3: When the Azure ML pipeline is executed, the `data_ingestion.py` script queries Bing Image Search for each class name and downloads images from the search results. Due to the attacker's manipulation, the search results now contain malicious images, which could be mislabeled, contain adversarial patterns, or be entirely irrelevant to the intended class.
    - Step 4: The `data_ingestion.py` script saves these downloaded images into the raw data directory, effectively injecting the malicious images into the training dataset.
    - Step 5: Subsequent steps of the pipeline, including data preprocessing, model training, and deployment, utilize this poisoned dataset.
    - Step 6: The machine learning model is trained on the contaminated dataset, leading to model poisoning. The poisoned model exhibits degraded performance, misclassifications, or biased predictions, as it has learned from the injected malicious data.
- **Impact:**
    - The primary impact is the compromise of the object classification model's integrity and reliability.
    - The model's accuracy and performance will be degraded, potentially leading to misclassification of objects in real-world applications.
    - In a security-sensitive context, this vulnerability could be exploited to bypass object detection systems, introduce targeted misclassifications, or subtly bias the model's predictions for malicious purposes.
    - The trustworthiness of the entire Azure ML pipeline and the deployed service is undermined, as the model's output can no longer be considered reliable.
- **Vulnerability Rank:** High
- **Currently Implemented Mitigations:**
    - There are no effective mitigations implemented in the provided code to prevent model poisoning via Bing Image Search manipulation.
    - The `data_ingestion.py` script includes a basic check for 'jpeg' image format and a timeout for image downloads, but these do not address content validation or source verification to prevent malicious image injection.
- **Missing Mitigations:**
    - Input Validation and Sanitization: Implement robust checks to validate the content and source of downloaded images. This could include:
        - Image format validation using a dedicated library to ensure image integrity and prevent malformed files.
        - Basic image property checks (e.g., size, resolution, color depth) to detect anomalies and potential manipulation.
        - Content-based image analysis (e.g., using perceptual hashing or feature extraction) to detect near-duplicate images or compare against a trusted baseline dataset, although this is computationally intensive.
    - Data Source Verification: Explore methods to verify the trustworthiness of image sources from Bing Search results. This is challenging with web-scraped data but could involve:
        - Reputation-based filtering of image sources (if Bing API provided source reputation, which it does not).
        - Domain whitelisting or blacklisting (less effective for broad search results and easily bypassed).
    - Anomaly Detection during Data Ingestion and Training: Implement anomaly detection mechanisms to identify suspicious data points during ingestion and training:
        - Monitor download patterns for unusual spikes or sources.
        - Track data distribution and statistics for unexpected shifts or outliers.
        - During training, monitor loss and accuracy curves for sudden drops or fluctuations that could indicate data poisoning.
    - Human-in-the-loop Validation: Introduce a manual review step for the ingested data, especially for critical applications. This could involve:
        - Randomly sampling and manually inspecting downloaded images to check for malicious or mislabeled content.
        - Providing a mechanism for users to flag and remove suspicious images from the dataset.
    - Dataset Versioning and Caching: Implement dataset versioning and caching to maintain a history of datasets and enable rollback to a known clean version if poisoning is detected. This does not prevent initial poisoning but aids in recovery and reproducibility.
- **Preconditions:**
    - The attacker must have the ability to influence or manipulate Bing Image Search results for the target class names used in the `data_ingestion.py` script. This typically requires skills in SEO poisoning, website compromise, or other techniques to manipulate search engine rankings.
    - The Azure ML pipeline must be configured to execute the `data_ingestion.py` script to fetch training data from Bing Image Search.
    - The attacker needs to know or be able to guess the class names used by the data ingestion script. In this case, the class names are based on the publicly known CIFAR-10 dataset classes, making them easily discoverable.
- **Source Code Analysis:**
    - File: `/code/modules/ingestion/data_ingestion.py`
        ```python
        import os
        import requests
        import argparse
        from time_util import time_limit

        # ... (ArgumentParser and argument parsing) ...

        # Set search headers and URL
        headers = requests.utils.default_headers()
        headers['User-Agent'] = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.87 Safari/537.36'

        # Define API endpoints
        subscription_key = os.environ['BING_SEARCH_V7_SUBSCRIPTION_KEY']
        endpoint = os.environ['BING_SEARCH_V7_ENDPOINT']
        search_url = endpoint + "v7.0/images/search"

        # Define classes
        classes = ['airplane', 'automobile', 'bird', 'cat', 'deer', 'dog', 'frog', 'horse', 'ship', 'truck']

        # Make query for each class and download images
        for name in classes:

            dir_name = os.path.join(output_dir, name)
            if not os.path.exists(dir_name):
                os.makedirs(dir_name)

            counter = 0
            num_searches = int(num_images/150)+1

            for i in range(num_searches):

                response = requests.get(
                    search_url,
                    headers = {
                        'Ocp-Apim-Subscription-Key' : subscription_key
                    },
                    params = {
                        'q': name,
                        'imageType': 'photo',
                        'count': 150,
                        'offset': i*150
                    })
                response.raise_for_status()
                results = response.json()["value"]

                for image in results:
                    if counter > num_images:
                        break
                    if image['encodingFormat'] == 'jpeg': # Vulnerability: Only checks for jpeg format
                        print('Writing image {} for {}...'.format(counter, name))
                        filename = '{}/{}.jpg'.format(dir_name, counter)
                        try:
                            with time_limit(5): # Timeout for download
                                with open(filename, 'wb') as file:
                                    download = requests.get(image['contentUrl'], headers=headers) # Vulnerability: Downloads image directly from URL
                                    file.write(download.content) # Vulnerability: No content validation
                                counter += 1
                        except:
                            print('Skipping {} due to download error:'.format(filename)) # Basic error handling, but no security checks
    ```
    - The code directly fetches images from URLs provided by Bing Image Search results without any content-based validation or source verification.
    - The only validation performed is a check for 'jpeg' encoding format, which is insufficient to prevent malicious image injection.
    - The script blindly trusts the search results and downloads images, making it vulnerable to model poisoning if an attacker can manipulate these results.

- **Security Test Case:**
    - Step 1: Set up the Azure ML pipeline in your Azure environment as described in the project's README.md. Ensure you have configured the necessary Azure services and have the pipeline running.
    - Step 2: Choose a target class from the predefined classes (e.g., 'cat').
    - Step 3: Prepare a set of malicious images. These images could be:
        - Images of a different class mislabeled as the target class (e.g., images of dogs labeled as cats).
        - Images containing adversarial patterns designed to confuse the object classification model when associated with the target class.
        - Corrupted images designed to cause issues during training.
    - Step 4: Simulate the attacker's manipulation of Bing Image Search results. Due to the complexity of actually poisoning Bing search results, this step will be a simulation. For a simplified test, you can:
        - **Option A (Simulated Network Interception):** Modify your local network settings or use a proxy to intercept the requests from `data_ingestion.py` to the Bing Image Search API. Replace the legitimate search results with a crafted JSON response that points to your prepared malicious images hosted on publicly accessible URLs.
        - **Option B (Manual Dataset Modification):** After the data ingestion step has run once and downloaded a legitimate dataset, manually replace a portion of the images in the 'cat' directory within the `raw_data_dir` datastore with your prepared malicious images. This bypasses the search manipulation but still tests the effect of poisoned data on the model.
    - Step 5: Run the Azure ML pipeline. Ensure that the pipeline executes all steps, including data ingestion, preprocessing, training, evaluation, and deployment.
    - Step 6: Monitor the pipeline run, especially the data ingestion and training steps. Check the logs for any errors or unusual behavior. If using Option A, verify that your malicious image URLs are being accessed during data ingestion.
    - Step 7: After the pipeline completes and the model is deployed, use the `test-endpoint.py` script to test the deployed service.
        - Test with legitimate images of 'cats' and observe the model's predictions.
        - Test with the malicious images you prepared and observe the model's predictions.
    - Step 8: Analyze the results:
        - If the model's accuracy on legitimate 'cat' images has significantly decreased compared to a baseline model trained on a clean dataset, this indicates successful model poisoning.
        - If the model misclassifies the malicious images (e.g., adversarial images still classified as 'cat', or dog images misclassified as 'cat'), this further confirms the poisoning effect.
        - If using Option B, compare the performance of the model trained with the manually poisoned dataset to the performance of a model trained on the original, clean dataset.
    - Step 9: Document your findings, including the steps taken, the observed impact on model performance, and the evidence of successful model poisoning. This test case demonstrates the vulnerability of the pipeline to data poisoning through manipulated search engine results and the lack of sufficient input validation in the data ingestion process.

### Vulnerability 3: Server-Side Request Forgery (SSRF) in test-endpoint.py

- **Description:**
    - The `test-endpoint.py` script takes an image URL as a command-line argument (`--image_url`).
    - It uses `urllib.request.urlopen(image_url)` to fetch the image from the provided URL.
    - The script then converts the image to base64 and sends it to the deployed Azure Machine Learning endpoint for object classification.
    - If an attacker provides a malicious URL instead of a legitimate image URL, the `urllib.request.urlopen` function will attempt to access the resource at that URL from the server hosting the Azure Machine Learning endpoint.
    - This could allow an attacker to perform a Server-Side Request Forgery (SSRF) attack.
    - For example, an attacker could provide a URL pointing to internal services within the Azure environment or to the metadata endpoint of the Azure instance.
- **Impact:**
    - An attacker could potentially gain access to internal resources or sensitive information accessible to the Azure Machine Learning endpoint.
    - In the context of Azure, this could include accessing the instance metadata service to retrieve sensitive information like credentials, configuration details, or access tokens.
    - An attacker might be able to probe internal network infrastructure, potentially identifying and interacting with other internal services that are not intended to be publicly accessible.
- **Vulnerability Rank:** High
- **Currently Implemented Mitigations:**
    - There are no input validation or sanitization mechanisms implemented in `test-endpoint.py` to prevent SSRF. The script directly uses the user-provided URL without any checks.
- **Missing Mitigations:**
    - Input validation and sanitization for the `image_url` parameter in `test-endpoint.py` is missing.
    - A whitelist of allowed URL schemes (e.g., only `http://` and `https://`) and hostnames could be implemented.
    - URL parsing and validation to prevent access to internal IP ranges or restricted hostnames should be added.
    - Consider using a dedicated library for URL handling and validation to avoid common pitfalls.
- **Preconditions:**
    - The Azure Machine Learning pipeline must be deployed and the web service endpoint must be publicly accessible.
    - An attacker needs to know or guess the scoring URI of the deployed web service. This information might be obtained through reconnaissance or by observing network traffic if the endpoint is used.
- **Source Code Analysis:**
    - File: `/code/test-endpoint.py`
    ```python
    import urllib.request
    # ... other imports ...
    import argparse

    # Define arguments
    parser = argparse.ArgumentParser(description='Test script parser')
    parser.add_argument('--image_url', type=str, help='URL of the image to score', default='https://compote.slate.com/images/222e0b84-f164-4fb1-90e7-d20bc27acd8c.jpg')
    image_url = parser.parse_args().image_url # [VULNERABLE CODE] User-provided URL is directly assigned

    # ... get scoring url ...

    # Download image and convert to base 64
    with urllib.request.urlopen(image_url) as url: # [VULNERABLE CODE] URL is used without validation
        test_img = io.BytesIO(url.read())

    # ... rest of the code ...
    ```
    - The vulnerability lies in the direct usage of the `image_url` variable, which is derived from user input, within `urllib.request.urlopen()`.
    - No validation or sanitization is performed on `image_url` before making the request.
    - An attacker can control the `image_url` parameter and make the server-side application send requests to arbitrary URLs.
- **Security Test Case:**
    - Precondition: Deploy the Azure Machine Learning pipeline and obtain the scoring URI of the deployed web service.
    - Step 1: Prepare a malicious URL. For testing SSRF on Azure, a common target is the instance metadata endpoint: `http://169.254.169.254/metadata/instance?api-version=2021-08-01`. This endpoint, when accessed from within an Azure VM, reveals instance metadata, potentially including sensitive information.
    - Step 2: Execute the `test-endpoint.py` script, providing the malicious URL as the `--image_url` argument:
    ```bash
    python test-endpoint.py --image_url http://169.254.169.254/metadata/instance?api-version=2021-08-01
    ```
    - Step 3: Observe the output and server-side logs (if accessible).
    - Expected Outcome:
        - If the vulnerability is present, the `urllib.request.urlopen` call will attempt to access the metadata endpoint from the server hosting the deployed service.
        - The response from the metadata endpoint (which could contain sensitive instance information) might be visible in the logs of the Azure Machine Learning endpoint, or indirectly observable through error messages if the response is not properly handled when it's not an image.
        - Even if the raw response is not directly returned to the attacker in the standard output, an indication of successful SSRF would be observing delays or errors related to accessing the internal metadata service, or observing network requests originating from the service's IP address to the internal IP `169.254.169.254` in server-side network logs (if available).
        - Note: Direct reflection of the metadata content in the standard output might not be guaranteed due to how the script processes the fetched content. However, the SSRF vulnerability is confirmed if the service attempts to access the internal URL, which can be verified through network monitoring or error behavior.