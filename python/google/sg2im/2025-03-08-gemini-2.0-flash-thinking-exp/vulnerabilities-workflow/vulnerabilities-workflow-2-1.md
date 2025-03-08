- Vulnerability Name: Uncontrolled Resource Consumption via Large Scene Graph
- Description: The `run_model.py` script processes scene graph JSON files. A maliciously crafted scene graph JSON file with an extremely large number of objects and relationships can be provided as input via the `--scene_graphs` argument. When the script loads and processes this large scene graph, it can lead to excessive memory consumption and potentially crash the application or cause significant performance degradation due to resource exhaustion.
- Impact: High
- Vulnerability Rank: High
- Currently Implemented Mitigations: None
- Missing Mitigations:
    - Input validation to limit the maximum number of objects and relationships in the scene graph JSON.
    - Resource limits to prevent excessive memory consumption during scene graph processing.
- Preconditions:
    - Attacker has access to run `scripts/run_model.py` with arbitrary `--scene_graphs` input.
- Source Code Analysis:
    - File: `/code/scripts/run_model.py`
    - The `run_model.py` script takes `--scene_graphs_json` argument which specifies the path to the scene graph JSON file.
    - The script loads the scene graph using `json.load(f)`:
      ```python
      with open(args.scene_graphs_json, 'r') as f:
        scene_graphs = json.load(f)
      ```
    - File: `/code/sg2im/model.py`
    - The `encode_scene_graphs` function in `Sg2ImModel` processes the loaded JSON:
      ```python
      def encode_scene_graphs(self, scene_graphs):
          # ...
          objs, triples, obj_to_img = [], [], []
          obj_offset = 0
          for i, sg in enumerate(scene_graphs):
              # ...
              for obj in sg['objects']:
                  # ...
                  objs.append(obj_idx)
                  obj_to_img.append(i)
              for s, p, o in sg['relationships']:
                  # ...
                  triples.append([s + obj_offset, pred_idx, o + obj_offset])
              obj_offset += len(sg['objects'])
          # ...
      ```
    - The code iterates through `sg['objects']` and `sg['relationships']` and appends them to lists `objs` and `triples`. If a large JSON is provided with thousands or millions of objects and relationships, these lists can grow very large, consuming significant memory. There are no explicit checks to limit the size of these lists based on the input JSON content.
- Security Test Case:
    - Step 1: Create a large scene graph JSON file (e.g., `large_scene_graph.json`) with thousands of objects and relationships. A simple python script can generate this file:
      ```python
      import json

      large_sg = {
          "objects": [f"object_{i}" for i in range(10000)],
          "relationships": [[i, "relation", i+1] for i in range(9999)]
      }

      with open("large_scene_graph.json", "w") as f:
          json.dump([large_sg], f)
      ```
    - Step 2: Run `scripts/run_model.py` providing the crafted JSON file as input:
      ```bash
      python scripts/run_model.py --checkpoint sg2im-models/vg128.pt --scene_graphs_json large_scene_graph.json --output_dir output_large_sg
      ```
    - Step 3: Observe the memory usage of the `run_model.py` process. It should significantly increase, potentially leading to a crash or slowdown depending on system resources. Monitor system resources during the execution of the script. If the system becomes unresponsive or the process is killed due to out-of-memory, it confirms the vulnerability.