- Vulnerability Name: Path Traversal in Dataset Loading
- Description:
    - An attacker crafts a malicious dataset.
    - This dataset contains image paths that use path traversal sequences (e.g., "../../") to point to files outside the intended dataset directory.
    - A user, intending to process a seemingly benign dataset, uses `create_text_data.py` to generate an LMDB file from this malicious dataset.
    - The `createDataset` function in `create_text_data.py`, when processing the malicious dataset, uses `PIL.Image.open(imagePath)` to open image files based on the provided paths.
    - If `PIL.Image.open` resolves path traversal sequences and accesses files outside the intended dataset directory, an attacker can potentially read arbitrary files from the system.
- Impact:
    - An attacker can potentially read arbitrary files from the system by crafting a malicious dataset. This can lead to information disclosure of sensitive data like configuration files, private keys, or other application data.
- Vulnerability Rank: Medium
- Currently Implemented Mitigations:
    - None
- Missing Mitigations:
    - Path sanitization: Sanitize the image paths in `create_img_label_list` and `createDataset` to prevent path traversal sequences. For example, use `os.path.abspath` to resolve paths and then check if the resolved path is within the intended dataset directory.
    - Input validation: Validate the dataset structure and file paths before processing to ensure they conform to expected patterns and do not contain path traversal sequences.
- Preconditions:
    - An attacker can create a malicious dataset and make it accessible to users.
    - A user downloads and attempts to process this malicious dataset using `create_text_data.py`.
- Source Code Analysis:
    - File: `/code/data/create_text_data.py`
    - Function: `createDataset`
    - Vulnerable code snippet:
      ```python
      def createDataset(image_path_list, label_list, outputPath, mode, author_id, remove_punc, resize, imgH, init_gap, h_gap, charminW, charmaxW, discard_wide, discard_narr, labeled):
          # ...
          for i in tqdm(range(nSamples)):
              imagePath = image_path_list[i] # Potentially malicious path from dataset
              label = label_list[i]
              # ...
              try:
                  im = Image.open(imagePath) # Vulnerable line, opens file based on potentially malicious path
              except:
                  continue
              # ...
      ```
    - The `imagePath` variable, derived from `image_path_list`, is directly used in `PIL.Image.open()`. If `image_path_list` is populated with path traversal strings, `Image.open()` might follow these paths, leading to files being opened outside the intended dataset directory.
- Security Test Case:
    1. Create a directory named `malicious_dataset`.
    2. Inside `malicious_dataset`, create a file named `sensitive_data.txt` with content "This is sensitive data.".
    3. Create a python script `generate_malicious_list.py` in the `/code/data` directory:
       ```python
       import os

       malicious_paths = ["../../malicious_dataset/sensitive_data.txt"]
       malicious_labels = [""] * len(malicious_paths)

       with open("malicious_images.txt", "w") as f:
           for path in malicious_paths:
               f.write(path + "\\n")

       with open("malicious_labels.txt", "w") as f:
           for label in malicious_labels:
               f.write(label + "\\n")
       ```
    4. Run `python /code/data/generate_malicious_list.py`. This will create `malicious_images.txt` and `malicious_labels.txt` in `/code/data` directory.
    5. Modify `/code/data/create_text_data.py` to read image paths and labels from these text files for testing purposes.  Replace the dataset-specific path generation in `if __name__ == '__main__':` block with reading from these lists:
       ```python
       if __name__ == '__main__':
           # ... comment out or remove dataset specific path creation ...
           image_path_list = []
           label_list = []
           with open("malicious_images.txt", "r") as f:
               for line in f:
                   image_path_list.append(line.strip())
           with open("malicious_labels.txt", "r") as f:
               for line in f:
                   label_list.append(line.strip())
           outputPath = "lmdb_malicious_dataset" # Define output path
           # ... rest of the createDataset call ...
       ```
    6. Run `python /code/data/create_text_data.py`.
    7. After running, manually examine the created LMDB database (`lmdb_malicious_dataset`) or check for any errors during the script execution that might indicate an attempt to access or process `sensitive_data.txt`. If the script runs without errors and creates LMDB, further investigation is needed to confirm if the sensitive file was actually accessed and potentially included in the LMDB (e.g. by checking file metadata or content within LMDB, if possible without dedicated tools). If errors related to image processing or file access occur, it might still indicate an attempt to open the out-of-directory file.