## Vulnerability Report

The following vulnerabilities have been identified in the provided lists.

### 1. Uncontrolled Resource Consumption via Large Scene Graph

- **Vulnerability Name:** Uncontrolled Resource Consumption via Large Scene Graph
- **Description:** The `run_model.py` script processes scene graph JSON files. A maliciously crafted scene graph JSON file with an extremely large number of objects and relationships can be provided as input via the `--scene_graphs` argument. When the script loads and processes this large scene graph, it can lead to excessive memory consumption and potentially crash the application or cause significant performance degradation due to resource exhaustion.
- **Impact:** High
- **Vulnerability Rank:** High
- **Currently Implemented Mitigations:** None
- **Missing Mitigations:**
    - Input validation to limit the maximum number of objects and relationships in the scene graph JSON.
    - Resource limits to prevent excessive memory consumption during scene graph processing.
- **Preconditions:**
    - Attacker has access to run `scripts/run_model.py` with arbitrary `--scene_graphs` input.
- **Source Code Analysis:**
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
- **Security Test Case:**
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

### 2. Command Injection via GraphViz in Scene Graph Visualization

- **Vulnerability Name:** Command Injection via GraphViz in Scene Graph Visualization
- **Description:**
    1. The application allows users to provide scene graph data in JSON format via the `--scene_graphs_json` argument.
    2. When the `--draw_scene_graphs 1` option is enabled, the application attempts to generate visual representations of these scene graphs using GraphViz.
    3. The `scripts/run_model.py` script reads the scene graph JSON and, for each scene graph, extracts the 'objects' and 'relationships' lists.
    4. These lists, directly derived from the user-provided JSON input, are then passed as arguments to the `sg2im/vis.py:draw_scene_graph` function.
    5. Inside `draw_scene_graph`, the object and relationship names from the input are incorporated into a GraphViz DOT language specification string.
    6. This DOT string is then written to a temporary file.
    7. Finally, the `os.system` function is used to execute the `dot` command-line utility from GraphViz, with the DOT file as input and an output image file path.
    8. Because the object and relationship names from the user-provided JSON are not sanitized before being embedded into the DOT command string and executed via `os.system`, an attacker can inject arbitrary commands. By crafting a malicious scene graph JSON with specially crafted object or relationship names, an attacker can execute arbitrary shell commands on the server when the `--draw_scene_graphs 1` option is used.
- **Impact:** Critical
- **Vulnerability Rank:** Critical
- **Currently Implemented Mitigations:** None
- **Missing Mitigations:**
    - **Input Sanitization**: The application lacks proper sanitization of object and relationship names extracted from the user-provided scene graph JSON before passing them to the `draw_scene_graph` function.
    - **Secure Command Execution**: Instead of using `os.system`, which is vulnerable to shell injection, the application should use safer alternatives for executing external commands, such as `subprocess.run` with proper argument handling to avoid shell interpretation.
    - **Disabling GraphViz by Default**: The scene graph drawing functionality using GraphViz should be disabled by default and clearly documented as potentially unsafe when used with untrusted scene graph data.
- **Preconditions:**
    1. The application must be running with the `--draw_scene_graphs 1` option enabled.
    2. GraphViz must be installed on the system where the application is running.
    3. An attacker must be able to provide a malicious scene graph JSON file to the application, typically via the `--scene_graphs_json` argument.
- **Source Code Analysis:**
    - File: `/code/scripts/run_model.py`
        ```python
        if args.draw_scene_graphs == 1:
            for i, sg in enumerate(scene_graphs):
              sg_img = vis.draw_scene_graph(sg['objects'], sg['relationships'])
              sg_img_path = os.path.join(args.output_dir, 'sg%06d.png' % i)
              imwrite(sg_img_path, sg_img)
        ```
        - This code snippet in `scripts/run_model.py` iterates through the loaded scene graphs and, if `--draw_scene_graphs` is enabled, calls `vis.draw_scene_graph` with `sg['objects']` and `sg['relationships']` directly from the parsed JSON.

    - File: `/code/sg2im/vis.py`
        ```python
        def draw_scene_graph(objs, triples, vocab=None, **kwargs):
          # ...
          lines = [
            'digraph{',
            'graph [size="5,3",ratio="compress",dpi="300",bgcolor="transparent"]',
            'rankdir=%s' % rankdir,
            'nodesep="0.5"',
            'ranksep="0.5"',
            'node [shape="box",style="rounded,filled",fontsize="48",color="none"]',
            'node [fillcolor="lightpink1"]',
          ]
          # Output nodes for objects
          for i, obj in enumerate(objs):
            if ignore_dummies and obj == '__image__':
              continue
            lines.append('%d [label="%s"]' % (i, obj)) # UNSAFE: obj is directly from user input

          # Output relationships
          next_node_id = len(objs)
          lines.append('node [fillcolor="lightblue1"]')
          for s, p, o in triples:
            if ignore_dummies and p == '__in_image__':
              continue
            lines += [
              '%d [label="%s"]' % (next_node_id, p), # UNSAFE: p is directly from user input
              '%d->%d [penwidth=%f,arrowsize=%f,weight=%f]' % (
                s, next_node_id, edge_width, arrow_size, binary_edge_weight),
              '%d->%d [penwidth=%f,arrowsize=%f,weight=%f]' % (
                next_node_id, o, edge_width, arrow_size, binary_edge_weight)
            ]
            next_node_id += 1
          lines.append('}')

          # ...
          os.system('dot -T%s %s > %s' % (output_format, dot_filename, output_filename)) # VULNERABLE: os.system is used with potentially malicious input
          # ...
        ```
        - In `sg2im/vis.py:draw_scene_graph`, the code constructs the DOT language string by directly embedding `obj` and `p` from the input lists into the `label` attribute of DOT nodes.  `os.system` is then used to execute the `dot` command, making it vulnerable to command injection if `obj` or `p` contains malicious shell commands.
- **Security Test Case:**
    - Step 1: Save the following malicious JSON payload to a file named `malicious_scene_graph.json`:
        ```json
        [
          {
            "objects": ["object1", "`touch /tmp/pwned`"],
            "relationships": []
          }
        ]
        ```
        - This JSON contains a scene graph with an object name designed to inject a command.
    - Step 2: Run the `scripts/run_model.py` script with the malicious JSON and enable scene graph drawing:
        ```bash
        python scripts/run_model.py --checkpoint sg2im-models/vg128.pt --scene_graphs_json malicious_scene_graph.json --output_dir output_test --draw_scene_graphs 1
        ```
        - **Note**: Ensure you have GraphViz installed (`sudo apt-get install graphviz` on Ubuntu) and `sg2im-models/vg128.pt` is available (download using `bash scripts/download_models.sh`).
    - Step 3: Check if the command injection was successful by verifying if the file `/tmp/pwned` was created:
        ```bash
        ls /tmp/pwned
        ```
        - If the file `/tmp/pwned` exists, it confirms that the command injection vulnerability is present, and the `touch /tmp/pwned` command was executed by the `os.system` call within `draw_scene_graph`.