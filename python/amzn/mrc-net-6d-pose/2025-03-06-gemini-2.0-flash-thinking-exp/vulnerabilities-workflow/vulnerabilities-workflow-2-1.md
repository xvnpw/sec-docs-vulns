- Vulnerability Name: Path Traversal in Inference Script via `dataset` and `output_suffix` parameters
  - Description:
    1. The `run_inference.sh` script takes `DATASET` and `SUFFIX` variables as input, which are passed to `inference.py` as the `--dataset` and `--output_suffix` arguments respectively.
    2. The `inference.py` script uses the `--dataset` argument to construct file paths, likely within functions like `dataset_params.get_model_params` and `dataset_params.get_split_params`. The `--output_suffix` is used to construct the output file name: `est_pose_file = '{}/mrcnet_{}-test_{}.csv'.format(p['eval_root'], p['dataset'], p['output_suffix_name'])` where `p['output_suffix_name'] = '{}_{}'.format(args.checkpoint_name, args.output_suffix)`.
    3. If an attacker can modify the `DATASET` or `SUFFIX` variables in `run_inference.sh` to include path traversal characters (e.g., `../`), they could potentially access or create files outside of the intended directories.
    4. For example, setting `DATASET=../../../../etc/passwd` might cause the application to attempt to open `/path/to/bop_root/../../../../etc/passwd/model_info.json`, potentially exposing system files. Setting `SUFFIX=../../../../tmp/output` might cause the application to write output CSV to `/tmp/output.csv` overwriting potentially sensitive files if the application has write permissions there.
  - Impact:
    - Arbitrary File Read: An attacker could read arbitrary files from the server's file system, including sensitive configuration files, code, or data by manipulating `DATASET`.
    - Arbitrary File Write (potentially): An attacker could write or overwrite arbitrary files on the server's file system by manipulating `SUFFIX`, if the application has write permissions to those locations.
  - Vulnerability Rank: High
  - Currently Implemented Mitigations: None
  - Missing Mitigations:
    - Input validation and sanitization for the `dataset` and `output_suffix` parameters to prevent path traversal characters.
    - Using secure file path construction methods that prevent traversal, regardless of input.
    - Restricting write permissions to output directories.
  - Preconditions:
    - The attacker needs to be able to modify the `DATASET` or `SUFFIX` variables in `run_inference.sh` or directly call `inference.py` with malicious `--dataset` or `--output_suffix` arguments.
  - Source Code Analysis:
    1. `/code/scripts/run_inference.sh`: The script defines `DATASET` and `SUFFIX` variables and passes them as `--dataset` and `--output_suffix` arguments to `inference.py`.
       ```bash
       DATASET=tless
       SUFFIX=0320
       python inference.py --dataset $DATASET --output_suffix $SUFFIX ...
       ```
    2. `/code/inference.py`: The script parses the `--dataset` and `--output_suffix` arguments and stores them in `args.dataset` and `args.output_suffix`.
       ```python
       parser = argparse.ArgumentParser()
       parser.add_argument('--dataset', type=str, required=True)
       parser.add_argument('--output_suffix', type=str, default='')
       args = parser.parse_args()
       dataset_name = args.dataset
       output_suffix = args.output_suffix
       ```
    3. The `dataset_name` variable is then used to construct file paths for reading model information. The `output_suffix` is used to construct the output file path for saving inference results.
       ```python
       p = {
           'dataset': args.dataset,
           'bop_root': bop_cfg.DATASET_ROOT,
           'eval_root': bop_cfg.EVAL_ROOT,
           'output_suffix_name': '{}_{}'.format(
               args.checkpoint_name, args.output_suffix),
           ...
       }
       dataset_id2cls = bop_cfg.DATASET_CONFIG[p['dataset']]['id2cls']
       dp_model = dataset_params.get_model_params(
           p['bop_root'], p['dataset'], model_type)
       dp_data = dataset_params.get_split_params(
           p['bop_root'], p['dataset'], 'test')
       with open(dp_model['models_info_path'], 'r') as fp: # Potential path traversal via dataset
           model_info = json.load(fp)

       est_pose_file = '{}/mrcnet_{}-test_{}.csv'.format(
           p['eval_root'], p['dataset'], p['output_suffix_name']) # Potential path traversal via dataset and output_suffix
       inout.save_bop_results(est_pose_file, bop19_pose_est_results) # File write here, potential path traversal via est_pose_file
       ```
  - Security Test Case:
    1. **Arbitrary File Read:**
       - Modify `/code/scripts/run_inference.sh`: Change the `DATASET` variable to a path traversal string:
         ```bash
         DATASET='../../../../etc/passwd'
         SUFFIX=0320
         ```
       - Run `/code/scripts/run_inference.sh`: `bash scripts/run_inference.sh`.
       - Observe output/errors: Check the output and error logs of `inference.py`. Look for errors related to accessing `/etc/passwd/model_info.json` or similar paths, indicating a path traversal attempt.
    2. **Arbitrary File Write:**
       - Modify `/code/scripts/run_inference.sh`: Change the `SUFFIX` variable to a path traversal string to write to `/tmp`:
         ```bash
         DATASET='tless'
         SUFFIX='../../../../tmp/output'
         ```
       - Run `/code/scripts/run_inference.sh`: `bash scripts/run_inference.sh`.
       - Check for file creation: After running, check if a file `output.csv` is created in the `/tmp` directory.
       - Verify file content: Examine the content of `/tmp/output.csv` to confirm if it contains the expected inference output data, which would confirm arbitrary file write capability.