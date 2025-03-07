- Vulnerability Name: Model Poisoning via Bing Image Search Manipulation
- Description:
    - Step 1: The `data_ingestion.py` script is designed to automatically build a training dataset by fetching images from Bing Image Search based on a predefined list of class names (e.g., airplane, automobile, bird, etc.).
    - Step 2: An attacker identifies the class names used by the script and manipulates Bing Image Search results for these terms. This manipulation can be achieved through various techniques such as Search Engine Optimization (SEO) poisoning, compromising websites that are indexed by Bing, or other methods to influence search engine rankings and image associations.
    - Step 3: When the Azure ML pipeline is executed, the `data_ingestion.py` script queries Bing Image Search for each class name and downloads images from the search results. Due to the attacker's manipulation, the search results now contain malicious images, which could be mislabeled, contain adversarial patterns, or be entirely irrelevant to the intended class.
    - Step 4: The `data_ingestion.py` script saves these downloaded images into the raw data directory, effectively injecting the malicious images into the training dataset.
    - Step 5: Subsequent steps of the pipeline, including data preprocessing, model training, and deployment, utilize this poisoned dataset.
    - Step 6: The machine learning model is trained on the contaminated dataset, leading to model poisoning. The poisoned model exhibits degraded performance, misclassifications, or biased predictions, as it has learned from the injected malicious data.
- Impact:
    - The primary impact is the compromise of the object classification model's integrity and reliability.
    - The model's accuracy and performance will be degraded, potentially leading to misclassification of objects in real-world applications.
    - In a security-sensitive context, this vulnerability could be exploited to bypass object detection systems, introduce targeted misclassifications, or subtly bias the model's predictions for malicious purposes.
    - The trustworthiness of the entire Azure ML pipeline and the deployed service is undermined, as the model's output can no longer be considered reliable.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - There are no effective mitigations implemented in the provided code to prevent model poisoning via Bing Image Search manipulation.
    - The `data_ingestion.py` script includes a basic check for 'jpeg' image format and a timeout for image downloads, but these do not address content validation or source verification to prevent malicious image injection.
- Missing Mitigations:
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
- Preconditions:
    - The attacker must have the ability to influence or manipulate Bing Image Search results for the target class names used in the `data_ingestion.py` script. This typically requires skills in SEO poisoning, website compromise, or other techniques to manipulate search engine rankings.
    - The Azure ML pipeline must be configured to execute the `data_ingestion.py` script to fetch training data from Bing Image Search.
    - The attacker needs to know or be able to guess the class names used by the data ingestion script. In this case, the class names are based on the publicly known CIFAR-10 dataset classes, making them easily discoverable.
- Source Code Analysis:
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

- Security Test Case:
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