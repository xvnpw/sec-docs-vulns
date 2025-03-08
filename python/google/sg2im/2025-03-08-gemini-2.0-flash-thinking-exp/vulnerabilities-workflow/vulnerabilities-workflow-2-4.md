- Vulnerability Name: Command Injection via GraphViz in Scene Graph Visualization

- Description:
    1. The application allows users to provide scene graph data in JSON format via the `--scene_graphs_json` argument.
    2. When the `--draw_scene_graphs 1` option is enabled, the application attempts to generate visual representations of these scene graphs using GraphViz.
    3. The `scripts/run_model.py` script reads the scene graph JSON and, for each scene graph, extracts the 'objects' and 'relationships' lists.
    4. These lists, directly derived from the user-provided JSON input, are then passed as arguments to the `sg2im/vis.py:draw_scene_graph` function.
    5. Inside `draw_scene_graph`, the object and relationship names from the input are incorporated into a GraphViz DOT language specification string.
    6. This DOT string is then written to a temporary file.
    7. Finally, the `os.system` function is used to execute the `dot` command-line utility from GraphViz, with the DOT file as input and an output image file path.
    8. Because the object and relationship names from the user-provided JSON are not sanitized before being embedded into the DOT command string and executed via `os.system`, an attacker can inject arbitrary commands. By crafting a malicious scene graph JSON with specially crafted object or relationship names, an attacker can execute arbitrary shell commands on the server when the `--draw_scene_graphs 1` option is used.

- Impact:
    - **Critical**: Successful command injection can allow an attacker to execute arbitrary code on the server hosting the application. This could lead to complete system compromise, data theft, malware installation, or denial of service.

- Vulnerability Rank: Critical

- Currently Implemented Mitigations:
    - None. The code directly uses `os.system` with unsanitized user input.

- Missing Mitigations:
    - **Input Sanitization**: The application lacks proper sanitization of object and relationship names extracted from the user-provided scene graph JSON before passing them to the `draw_scene_graph` function.
    - **Secure Command Execution**: Instead of using `os.system`, which is vulnerable to shell injection, the application should use safer alternatives for executing external commands, such as `subprocess.run` with proper argument handling to avoid shell interpretation.
    - **Disabling GraphViz by Default**: The scene graph drawing functionality using GraphViz should be disabled by default and clearly documented as potentially unsafe when used with untrusted scene graph data.

- Preconditions:
    1. The application must be running with the `--draw_scene_graphs 1` option enabled.
    2. GraphViz must be installed on the system where the application is running.
    3. An attacker must be able to provide a malicious scene graph JSON file to the application, typically via the `--scene_graphs_json` argument.

- Source Code Analysis:
    1. **File: /code/scripts/run_model.py**
        ```python
        if args.draw_scene_graphs == 1:
            for i, sg in enumerate(scene_graphs):
              sg_img = vis.draw_scene_graph(sg['objects'], sg['relationships'])
              sg_img_path = os.path.join(args.output_dir, 'sg%06d.png' % i)
              imwrite(sg_img_path, sg_img)
        ```
        This code snippet in `scripts/run_model.py` iterates through the loaded scene graphs and, if `--draw_scene_graphs` is enabled, calls `vis.draw_scene_graph` with `sg['objects']` and `sg['relationships']` directly from the parsed JSON.

    2. **File: /code/sg2im/vis.py**
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
        In `sg2im/vis.py:draw_scene_graph`, the code constructs the DOT language string by directly embedding `obj` and `p` from the input lists into the `label` attribute of DOT nodes.  `os.system` is then used to execute the `dot` command, making it vulnerable to command injection if `obj` or `p` contains malicious shell commands.

- Security Test Case:
    1. Save the following malicious JSON payload to a file named `malicious_scene_graph.json`:
        ```json
        [
          {
            "objects": ["object1", "`touch /tmp/pwned`"],
            "relationships": []
          }
        ]
        ```
        This JSON contains a scene graph with an object name designed to inject a command.
    2. Run the `scripts/run_model.py` script with the malicious JSON and enable scene graph drawing:
        ```bash
        python scripts/run_model.py --checkpoint sg2im-models/vg128.pt --scene_graphs_json malicious_scene_graph.json --output_dir output_test --draw_scene_graphs 1
        ```
        **Note**: Ensure you have GraphViz installed (`sudo apt-get install graphviz` on Ubuntu) and `sg2im-models/vg128.pt` is available (download using `bash scripts/download_models.sh`).
    3. Check if the command injection was successful by verifying if the file `/tmp/pwned` was created:
        ```bash
        ls /tmp/pwned
        ```
        If the file `/tmp/pwned` exists, it confirms that the command injection vulnerability is present, and the `touch /tmp/pwned` command was executed by the `os.system` call within `draw_scene_graph`.

This test case demonstrates how an attacker can inject and execute arbitrary commands by providing a malicious scene graph JSON when the `--draw_scene_graphs 1` option is enabled.