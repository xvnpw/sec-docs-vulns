- Vulnerability Name: Uncontrolled Resource Consumption in Scene Graph Encoding
- Description:
    1. An attacker crafts a malicious scene graph JSON file.
    2. This malicious scene graph contains an extremely large number of objects and relationships.
    3. The `encode_scene_graphs` function in `sg2im/model.py` processes this scene graph.
    4. Due to the lack of input validation and resource limits, the function allocates excessive memory to store objects, triples, and related data structures.
    5. This leads to uncontrolled resource consumption, potentially causing memory exhaustion or performance degradation in the application processing the scene graph.
- Impact:
    - High memory consumption leading to degraded performance or application instability.
    - Potential for denial of service if memory exhaustion crashes the application.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - None. The code does not implement any explicit checks or limits on the number of objects or relationships in the input scene graphs.
- Missing Mitigations:
    - Input validation: Implement checks to limit the maximum number of objects and relationships allowed in a scene graph.
    - Resource limits: Set limits on memory allocation or processing time for scene graph encoding to prevent excessive resource consumption.
- Preconditions:
    - The application using this code must be processing scene graphs provided by external or untrusted sources.
    - The attacker needs to be able to submit a crafted scene graph to the application.
- Source Code Analysis:
    1. **File: /code/sg2im/model.py, Function: encode_scene_graphs**
    ```python
    def encode_scene_graphs(self, scene_graphs):
        ...
        objs, triples, obj_to_img = [], [], []
        obj_offset = 0
        for i, sg in enumerate(scene_graphs):
            # Insert dummy __image__ object and __in_image__ relationships
            sg['objects'].append('__image__')
            image_idx = len(sg['objects']) - 1
            for j in range(image_idx):
                sg['relationships'].append([j, '__in_image__', image_idx])

            for obj in sg['objects']:
                ...
                objs.append(obj_idx)
                obj_to_img.append(i)
            for s, p, o in sg['relationships']:
                ...
                triples.append([s + obj_offset, pred_idx, o + obj_offset])
            obj_offset += len(sg['objects'])
        device = next(self.parameters()).device
        objs = torch.tensor(objs, dtype=torch.int64, device=device)
        triples = torch.tensor(triples, dtype=torch.int64, device=device)
        obj_to_img = torch.tensor(obj_to_img, dtype=torch.int64, device=device)
        return objs, triples, obj_to_img
    ```
    - The code iterates through `scene_graphs`, `sg['objects']`, and `sg['relationships']` and appends data to lists `objs`, `triples`, and `obj_to_img`.
    - The number of iterations and the size of these lists are directly controlled by the content of the input `scene_graphs`.
    - If a malicious scene graph with a very large number of objects and relationships is provided, these lists can grow very large, consuming significant memory.
    - Finally, `torch.tensor` is called to convert these lists into tensors, which will allocate memory on the device (CPU or GPU).
    - There are no checks on the size of `objs`, `triples`, or `obj_to_img` before tensor creation, meaning an attacker can cause excessive memory allocation by providing a large scene graph.

- Security Test Case:
    1. Create a JSON file `malicious_scene_graph.json` with a scene graph containing a very large number of objects and relationships (e.g., thousands or tens of thousands). Example structure:
    ```json
    [
        {
            "objects": ["object1", "object2", ..., "objectN"],
            "relationships": [
                [0, "relation1", 1],
                [0, "relation2", 2],
                ...,
                [N-2, "relationM", N-1]
            ]
        }
    ]
    ```
    where N and M are very large numbers.
    2. Run the `run_model.py` script with the `--scene_graphs_json malicious_scene_graph.json` and `--device cpu` (to make memory exhaustion more apparent on a typical machine).
    ```bash
    python scripts/run_model.py --checkpoint sg2im-models/vg128.pt --scene_graphs_json malicious_scene_graph.json --output_dir malicious_output --device cpu
    ```
    3. Observe the memory usage of the process. It should significantly increase, and in cases of extreme scene graph sizes, may lead to program termination due to out-of-memory errors or system slowdowns.
    4. To verify the vulnerability, monitor system memory usage during the execution of `run_model.py`. Tools like `top`, `htop`, or system monitor can be used to observe memory consumption. If memory usage increases drastically and potentially leads to errors or slowdowns, the vulnerability is confirmed.