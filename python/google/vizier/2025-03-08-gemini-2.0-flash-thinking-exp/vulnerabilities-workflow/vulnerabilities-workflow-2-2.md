- Vulnerability Name: Metric Name Injection

- Description:
    1. An attacker crafts a malicious study configuration using the User API.
    2. In this configuration, the attacker provides a specially crafted metric name that includes a payload, for example,  `"; malicious_command"`.
    3. The User API in `vizier/service/pyvizier.py` or related client libraries accepts this metric name without proper validation.
    4. This malicious metric name is then passed to the Vizier service.
    5. The Vizier service, while processing the study configuration, improperly handles or logs this metric name, potentially executing the injected payload or causing unintended behavior due to the unvalidated input.

- Impact:
    Information Disclosure, potential for further exploitation depending on how metric names are processed and logged within the Vizier service.

- Vulnerability Rank: Medium

- Currently Implemented Mitigations:
    None identified in the provided project files. The code in `/code/vizier/_src/service/vizier_client_test.py`, `/code/vizier/_src/service/constants.py`, `/code/vizier/_src/service/vizier_client.py`, `/code/vizier/_src/service/datastore_test_lib.py`, `/code/vizier/_src/service/vizier_service_test.py`, `/code/vizier/_src/service/service_policy_supporter.py`, `/code/vizier/_src/service/custom_errors.py`, `/code/vizier/_src/service/datastore.py`, `/code/vizier/_src/service/pythia_util.py`, `/code/vizier/_src/service/clients_test.py`, `/code/vizier/_src/service/performance_test.py`, `/code/vizier/_src/service/pythia_service.py`, `/code/vizier/_src/service/policy_factory.py`, `/code/vizier/_src/service/sql_datastore.py`, `/code/vizier/_src/service/vizier_service.py`, `/code/vizier/_src/service/resources.py`, `/code/vizier/_src/service/sql_datastore_test.py`, `/code/vizier/_src/service/ram_datastore_test.py`, `/code/vizier/_src/service/stubs_util.py`, `/code/vizier/_src/service/stubs_util_test.py`, `/code/vizier/_src/service/clients.py`, `/code/vizier/_src/service/ram_datastore.py`, `/code/vizier/_src/service/resources_test.py`, `/code/vizier/_src/service/types.py`, `/code/vizier/_src/service/testing/util.py`, `/code/vizier/pyglove/__init__.py`, `/code/vizier/testing/numpy_assertions.py`, `/code/vizier/testing/__init__.py`, `/code/vizier/testing/test_studies.py`, `/code/vizier/raytune/__init__.py`, `/code/vizier/utils/attrs_utils.py`, `/code/vizier/utils/json_utils_test.py`, `/code/vizier/utils/attrs_utils_test.py`, `/code/vizier/utils/json_utils.py`, `/code/vizier/utils/profiler.py`, `/code/vizier/utils/profiler_test.py`, `/code/vizier/client/client_abc.py`, `/code/vizier/client/client_abc_testing.py`, `/code/vizier/benchmarks/__init__.py`, `/code/vizier/benchmarks/analyzers.py`, `/code/vizier/benchmarks/experimenters/__init__.py`, `/code/vizier/benchmarks/experimenters/multiobjective_optproblems/__init__.py`, `/code/vizier/benchmarks/experimenters/hpo/__init__.py`, `/code/vizier/benchmarks/experimenters/rl/__init__.py`, `/code/vizier/benchmarks/experimenters/nas/__init__.py`, `/code/vizier/pyvizier/__init__.py`, `/code/vizier/pyvizier/converters/feature_mapper.py`, `/code/vizier/pyvizier/converters/embedder.py`, `/code/vizier/pyvizier/converters/padding_test.py`, `/code/vizier/pyvizier/converters/jnp_converters_test.py`, `/code/vizier/pyvizier/converters/input_warping_test.py`, `/code/vizier/pyvizier/converters/spatio_temporal_test.py`, `/code/vizier/pyvizier/converters/core.py`, `/code/vizier/pyvizier/converters/feature_mapper_test.py`, `/code/vizier/pyvizier/converters/jnp_converters.py`, `/code/vizier/pyvizier/converters/core_test.py`, `/code/vizier/pyvizier/converters/spatio_temporal.py`, `/code/vizier/pyvizier/converters/__init__.py`, `/code/vizier/pyvizier/converters/input_warping.py`, `/code/vizier/pyvizier/converters/padding.py`, `/code/vizier/pyvizier/converters/embedder_test.py`, `/code/vizier/pyvizier/multimetric/xla_pareto.py`, `/code/vizier/pyvizier/multimetric/__init__.py`, `/code/vizier/algorithms/evolution.py`, `/code/vizier/algorithms/__init__.py`, `/code/vizier/algorithms/designers/__init__.py`, `/code/vizier/algorithms/policies/__init__.py`, `/code/vizier/interfaces/serializable.py`, `/code/vizier/jax/models.py`, `/code/vizier/jax/optimizers.py`, `/code/vizier/jax/__init__.py`, `/code/vizier/service/__init__.py`, `/code/vizier/service/clients/__init__.py`, `/code/vizier/service/protos/__init__.py`, `/code/vizier/service/servers/__init__.py`, `/code/vizier/service/pyvizier/__init__.py`, `/code/docs/conf.py`, `/code/requirements.txt` do not include input validation for metric names.

- Missing Mitigations:
    - Input validation and sanitization for metric names within the User API and Vizier service.
    - Security test cases to specifically check for metric name injection vulnerabilities.

- Preconditions:
    1. Attacker needs access to the User API, either directly or through a client library.
    2. The Vizier service must be running and accessible to process study configurations.

- Source Code Analysis:
    Based on the provided files, there's no direct source code for User API or Vizier Service to analyze input validation. However, the `README.md` and `demos/run_vizier_client.py` show that metric names are passed as strings within the `StudyConfig` object:

    ```python
    study_config.metric_information.append(vz.MetricInformation('metric_name', goal=vz.ObjectiveMetricGoal.MAXIMIZE))
    ```

    This suggests that the `metric_name` parameter in `vz.MetricInformation` is a potential input point.  The `run_vizier_client.py` demo further illustrates how user-defined metric names are incorporated into the `StudyConfig` and used in `vz.Measurement`:

    ```python
    vz.Measurement({'metric_name': objective})
    ```

    Without access to the Vizier service code, it's assumed based on the vulnerability description that insufficient validation in the service could lead to exploitation. The `build_protos.sh` script suggests that protocol buffers are used for communication, and vulnerability could be present in the proto processing logic on the service side or in the client API if it's doing any processing before sending to the service.

- Security Test Case:
    1. Setup a Vizier service instance and ensure User API is accessible (as per `demos/run_vizier_server.py`).
    2. Create a Python client using the `google-vizier` library (as per `demos/run_vizier_client.py`).
    3. Construct a `StudyConfig` object in Python using the client library.
    4. In the `metric_information` section of `StudyConfig`, set the `name` of a metric to a malicious string, e.g., `";malicious_payload"`.

    ```python
    from vizier.service import clients
    from vizier.service import pyvizier as vz

    study_config = vz.StudyConfig(algorithm='DEFAULT')
    study_config.search_space.root.add_float_param('w', 0.0, 5.0)
    study_config.metric_information.append(vz.MetricInformation('metric_name;malicious_payload', goal=vz.ObjectiveMetricGoal.MAXIMIZE)) # Malicious metric name
    study = clients.Study.from_study_config(study_config, owner='test', study_id='metric-injection-test')
    suggestions = study.suggest(count=1)
    ```
    5. Execute the client code to create the study with the malicious metric name.
    6. Observe the Vizier service logs and behavior to see if the malicious payload within the metric name is processed or logged in an unsafe manner.
    7. Attempt to retrieve study information or metrics through the User API to check if the malicious payload has caused any unintended information disclosure or errors.
    8. If the service exhibits unexpected behavior or logs the malicious payload without sanitization, the vulnerability is confirmed.