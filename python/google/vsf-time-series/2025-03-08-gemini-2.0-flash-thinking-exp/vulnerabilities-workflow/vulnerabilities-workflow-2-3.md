### Vulnerability List

- Vulnerability Name: Data Poisoning via Compromised External Data Sources
- Description:
    - The project's README.md file directs users to download datasets from external, third-party websites and services, including:
        - [https://github.com/laiguokun/multivariate-time-series-data](https://github.com/laiguokun/multivariate-time-series-data) (SOLAR, TRAFFIC)
        - [Google Drive](https://drive.google.com/open?id=10FOTa6HXPqX8Pf5WRoRwcFnW9BrNZEIX) or [Baidu Yun](https://pan.baidu.com/s/14Yy9isAIZYdU__OYEQGa_g) (METR-LA)
        - [time series classification website](http://www.timeseriesclassification.com/description.php?Dataset=ECG5000) (ECG)
    - An attacker could compromise these external data sources by:
        - Gaining unauthorized access to the linked Google Drive or Baidu Yun accounts.
        - Compromising the servers hosting the linked websites.
        - Performing a man-in-the-middle attack on network traffic if the links are not using HTTPS.
    - Once compromised, the attacker could replace the legitimate datasets with poisoned datasets containing manipulated time-series data.
    - Users following the README.md instructions would download and use these poisoned datasets to train the models.
    - Models trained on poisoned data will learn from corrupted information, leading to inaccurate or potentially malicious predictions during inference.
- Impact:
    - Training models with poisoned datasets can lead to:
        - Degraded forecasting accuracy, making the models unreliable for their intended purpose.
        - Skewed or biased predictions, potentially leading to incorrect decisions in real-world applications.
        - In the worst case, intentionally manipulated predictions that could cause harm in applications like traffic control, energy management, or healthcare if these models are deployed in such critical systems.
        - Loss of trust in the model and the research project.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - None. The project relies entirely on the security of external websites and services. There are no mechanisms in place to verify the integrity or authenticity of the downloaded datasets.
- Missing Mitigations:
    - **Integrity Checks**: Implement checksum verification for the datasets. Provide SHA256 or similar checksums for each dataset in the README.md, allowing users to verify the integrity of downloaded files using tools like `sha256sum`.
    - **Secure Hosting**: Host the datasets within the project's repository itself using Git Large File Storage (LFS) or on a project-controlled, secure cloud storage service (e.g., AWS S3, Azure Blob Storage) with access controls. This reduces reliance on external, potentially less secure, third-party platforms.
    - **Data Source Verification Instructions**: Add clear instructions in the README.md on how users can independently verify the authenticity and integrity of the data sources, even if external links are used. This could include linking to official dataset websites or publications where the datasets are originally described.
    - **Data Sanitization and Anomaly Detection**: Implement basic data sanitization and anomaly detection checks within the `generate_training_data.py` script. This could involve checking for:
        - Out-of-range values based on expected data characteristics.
        - Sudden, unexpected jumps or drops in time-series values.
        - Statistical anomalies compared to historical data distributions.
        - While not foolproof, these checks can raise red flags and alert users to potential data corruption or manipulation.
- Preconditions:
    - An attacker must successfully compromise one or more of the external data sources linked in the README.md.
    - Users must follow the instructions in the README.md and download datasets from these compromised external sources.
    - Users must execute the `generate_training_data.py` script and subsequently train the models using the downloaded (and potentially poisoned) datasets.
- Source Code Analysis:
    - `/code/README.md`: This file is the primary source of the vulnerability. It contains the links to external data sources without any warnings about potential security risks or instructions for verifying data integrity.
    - `/code/generate_training_data.py`: This script is responsible for reading the raw data files specified by the `--dataset_filename` argument and preprocessing them into training, validation, and test sets.
        ```python
        import pandas as pd
        # ...
        def generate_train_val_test(args):
            if args.ds_name == "metr-la":
                df = pd.read_hdf(args.dataset_filename) # Reads HDF5 file without integrity checks
            else:
                df = pd.read_csv(args.dataset_filename, delimiter = ",", header=None) # Reads CSV file without integrity checks
            # ...
        ```
        - The script uses `pandas.read_hdf` and `pandas.read_csv` to read data files. These functions do not inherently perform any data integrity checks. If a malicious HDF5 or CSV file is provided as `--dataset_filename`, the script will process it without any validation.
    - `/code/train_multi_step.py`: This script uses the processed data generated by `generate_training_data.py` to train the model. It is not involved in data loading from external sources and does not contain any vulnerability related code.
- Security Test Case:
    1. **Attacker Compromises External Data Source (Simulated)**:
        - For testing purposes, we will simulate the compromise. Assume the attacker has replaced the METR-LA dataset on the Google Drive link in the README.md with a malicious version.
        - Create a modified `metr-la.h5` dataset (poisoned dataset). For example, subtly alter the traffic data values in the HDF5 file to introduce a bias (e.g., consistently lower traffic readings for specific sensors or time periods).
    2. **Victim Downloads Poisoned Dataset**:
        - The victim user follows the instructions in the README.md to download the METR-LA dataset from the (simulated) compromised Google Drive link and saves it as `data/metr-la.h5`.
    3. **Victim Generates Training Data**:
        - The victim runs the data generation script:
          ```bash
          python generate_training_data.py --ds_name metr-la --output_dir data/METR-LA --dataset_filename data/metr-la.h5
          ```
        - This script will process the poisoned `metr-la.h5` dataset and create `train.npz`, `val.npz`, and `test.npz` in the `data/METR-LA` directory.
    4. **Victim Trains Model**:
        - The victim trains the MTGNN model using the standard training command:
          ```bash
          python train_multi_step.py --data ./data/METR-LA --model_name mtgnn --device cuda:0 --expid 1 --epochs 2 --batch_size 64 --runs 1 --random_node_idx_split_runs 1 --lower_limit_random_node_selections 100 --upper_limit_random_node_selections 100 --step_size1 2500 --mask_remaining false
          ```
        - Train for a reduced number of epochs (e.g., 2) to quickly demonstrate the effect.
    5. **Victim Evaluates Model**:
        - After training, evaluate the model on the (potentially also poisoned, or a separate clean if available) test dataset.
        - Compare the evaluation metrics (MAE, RMSE) and predictions of the model trained on the poisoned data to a model trained on a clean, original METR-LA dataset.
    6. **Observe Impact**:
        - If the data poisoning is successful, the model trained on the poisoned dataset will exhibit:
            - Different evaluation metrics compared to the model trained on clean data.
            - Skewed or biased predictions, reflecting the manipulations introduced in the poisoned dataset. For example, if traffic data was lowered, the model might consistently under-predict traffic flow.

This test case demonstrates how an attacker, by compromising external data sources, can poison the training data and influence the behavior of the trained multivariate time series forecasting model.