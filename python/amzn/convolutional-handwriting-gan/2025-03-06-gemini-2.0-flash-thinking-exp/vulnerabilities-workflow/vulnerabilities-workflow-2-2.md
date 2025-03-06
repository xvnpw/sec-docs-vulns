### Vulnerability List

- Vulnerability Name: Path Traversal during LMDB creation
- Description:
    An attacker can craft a malicious dataset by replacing image files within the expected dataset structure (e.g., IAM, RIMES, CVL datasets in the `Datasets` directory) with symbolic links. These symbolic links can be designed to point to files or directories outside the intended dataset directory on the user's file system. When the `create_text_data.py` script processes this maliciously crafted dataset to generate an LMDB file, the script, through image processing libraries, follows these symbolic links. This can lead to the script accessing and potentially embedding content of arbitrary files from the user's system into the generated LMDB dataset.

    Steps to trigger the vulnerability:
    1.  Download a legitimate dataset (e.g., IAM, RIMES, or CVL) and place it in the `Datasets` directory as per the project's README instructions.
    2.  Identify image files within the downloaded dataset directory structure.
    3.  Replace some of these image files with symbolic links. These symbolic links should point to sensitive files outside the dataset directory, for example, system files like `/etc/passwd` or user-specific files. For example, in a Linux environment, you could use the `ln -s` command to create symbolic links.
    4.  Run the `create_text_data.py` script to generate an LMDB file from this modified dataset. For example, using the command `cd data && python create_text_data.py`. Ensure the script is configured to process the dataset you've modified (e.g., by setting `dataset = 'IAM'` inside `create_text_data.py` or via command-line arguments if they were implemented).
    5.  The `create_text_data.py` script will process the dataset, and when it encounters the symbolic links during image loading (using PIL's `Image.open` or similar), it will follow these links.
    6.  The content of the files pointed to by the symbolic links will be read and potentially embedded into the generated LMDB file as image data.
- Impact:
    Information Disclosure. Successful exploitation of this vulnerability can allow an attacker to read the contents of arbitrary files on the system where the `create_text_data.py` script is executed. The content of these files gets embedded into the generated LMDB dataset. If this LMDB dataset is then shared or used in further processes, it could inadvertently expose sensitive information. In a more severe scenario, depending on how the application processes the "image" data from the LMDB, there might be potential for further exploitation, although arbitrary code execution directly from this path traversal is less likely in this specific code context.
- Vulnerability Rank: Medium
- Currently Implemented Mitigations:
    None. The code does not implement any explicit checks to prevent path traversal during dataset processing or LMDB generation. The script naively opens and processes files based on paths found within the dataset structure without validating if these paths remain within the intended dataset boundaries.
- Missing Mitigations:
    - Path Sanitization and Validation: Implement checks within `create_text_data.py` to sanitize and validate all file paths before opening them. This should include verifying that resolved paths (after following symbolic links) still reside within the expected dataset root directory.
    - Symbolic Link Handling:  Implement secure handling of symbolic links. Options include:
        - Preventing symbolic link following altogether during dataset processing.
        - Resolving symbolic links and then strictly validating that the resolved path is within the allowed dataset directory.
    - Filesystem Sandboxing: Employ filesystem sandboxing or containerization to limit the script's access only to the intended dataset directory and prevent access to sensitive areas of the filesystem.
    - Input Validation: While the primary vulnerability is through dataset content, ensure that dataset names and modes passed as arguments are also validated against an allowed list to prevent any indirect path manipulation through argument injection, although this is less of a direct path traversal vector.
- Preconditions:
    1. The attacker needs to be able to provide a maliciously crafted dataset to the user. This could be achieved by tricking a user into downloading a compromised dataset from an untrusted source, or by social engineering to make the user process a dataset prepared by the attacker.
    2. The user must then execute the `create_text_data.py` script, or any other script that uses the vulnerable data loading process, on this malicious dataset.
- Source Code Analysis:
    In `/code/data/create_text_data.py`:
    - The `createDataset` function iterates through `image_path_list` and `label_list`. `image_path_list` is populated by functions like `create_img_label_list` which in turn read paths from either directory structures (CVL, IAM) or ground truth files (RIMES).
    - Inside the loop in `createDataset`, `Image.open(imagePath)` is called to open each image file.

    ```python
    def createDataset(image_path_list, label_list, outputPath, mode, author_id, remove_punc, resize, imgH, init_gap, h_gap, charminW, charmaxW, discard_wide, discard_narr, labeled):
        # ...
        for i in tqdm(range(nSamples)):
            imagePath = image_path_list[i]
            label = label_list[i]
            # ...
            try:
                im = Image.open(imagePath) # Vulnerable line: Image.open follows symlinks
            except:
                continue
            # ...
            imgByteArr = io.BytesIO()
            im.save(imgByteArr, format='tiff')
            wordBin = imgByteArr.getvalue()
            # ...
    ```
    - The `Image.open(imagePath)` function from PIL (Pillow) by default will follow symbolic links. If `imagePath` is a symbolic link pointing outside the dataset directory, PIL will open the target file.
    - There is no path validation or sanitization performed on `imagePath` before `Image.open` is called. The script trusts that the provided `image_path_list` contains paths to legitimate image files within the dataset.
- Security Test Case:
    1.  Set up a test environment with the ScrabbleGAN project code and the required dependencies (PyTorch, etc.).
    2.  Download the IAM dataset and place it in the `Datasets` directory.
    3.  Navigate to the IAM dataset's `wordImages` directory (e.g., `Datasets/IAM/wordImages/a01/a01-000u`).
    4.  In this directory, replace an image file, for example, `a01-000u-00.png`, with a symbolic link to a sensitive file. In a Linux environment, you can do this using:
        ```bash
        ln -sf /etc/passwd a01-000u-00.png
        ```
    5.  Navigate to the `data` directory in the ScrabbleGAN project (`cd code/data`).
    6.  Modify the `create_text_data.py` script to process the IAM dataset. Ensure the parameters inside `if __name__ == '__main__':` block are set as follows:
        ```python
        if __name__ == '__main__':
            create_Dict = False
            dataset = 'IAM'
            mode = 'tr'
            labeled = True
            top_dir = 'Datasets'
            words = True
            author_number = -1
            remove_punc = True
            resize = 'noResize'
            imgH = 32
            init_gap = 0
            charmaxW = 17
            charminW = 16
            h_gap = 0
            discard_wide = True
            discard_narr = True
        ```
    7.  Run the `create_text_data.py` script:
        ```bash
        python create_text_data.py
        ```
    8.  After the script completes, navigate to the output LMDB directory (e.g., `Datasets/IAM/words/noResize/tr_unlabeld_removePunc`).
    9.  Use an LMDB browser or write a script to read the content of the LMDB file. Look for the entry corresponding to the symbolic link you created (e.g., 'image-00000001' if it's the first image processed).
    10. Check if the content of this LMDB entry is now the content of `/etc/passwd` (or the file you linked to) instead of image data. If it is, the path traversal vulnerability is confirmed.