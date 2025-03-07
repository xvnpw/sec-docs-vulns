## Combined Vulnerability List

### Task Deletion Vulnerability via Malicious Markdown Injection

*   **Vulnerability Name:** Task Deletion Vulnerability via Malicious Markdown Injection

*   **Description:**
    1.  A malicious user can craft a Markdown file that, when processed by the `reconcile` command, causes the deletion of all tasks and task lists in the user's Google Tasks account.
    2.  This is achieved by exploiting the title-based matching logic in the `reconcile` function and injecting a specially crafted task list title in the malicious Markdown file.
    3.  When the `reconcile` function compares the old task lists (fetched from Google Tasks) with the new task lists (parsed from the malicious Markdown), it identifies all existing task lists as "to be deleted" because their titles do not match the injected malicious title.
    4.  Steps to trigger the vulnerability:
        *   The attacker crafts a malicious Markdown file with a task list title different from any of the user's existing task list titles (e.g., `# TODO\n\n## Malicious Task List Title`).
        *   The victim user executes the `reconcile` command using the malicious Markdown file: `gtasks-md reconcile malicious_tasks.md`.
        *   The `reconcile` command fetches task lists from Google Tasks and parses the malicious Markdown.
        *   Due to title mismatch, all existing task lists are marked for deletion.
        *   The `reconcile` function deletes all task lists and tasks from the user's Google Tasks account.

*   **Impact:**
    Critical data loss. All tasks and task lists in the user's Google Tasks account are permanently deleted, leading to significant disruption and loss of important task management data.

*   **Vulnerability Rank:** Critical

*   **Currently Implemented Mitigations:**
    None. The application lacks input validation or sanitization and relies solely on title matching without safeguards against malicious title manipulation.

*   **Missing Mitigations:**
    *   Input validation and sanitization for task list and task titles.
    *   Confirmation step before deleting task lists or tasks, especially for large deletions.
    *   Backup mechanism before reconciliation (currently backup is after fetching tasks but before reconcile operation and can be used).
    *   More robust reconciliation logic beyond title matching.
    *   User warning about risks of using `reconcile` with untrusted Markdown files.

*   **Preconditions:**
    *   Attacker tricks the user into using a malicious Markdown file with `reconcile`.
    *   User has authorized `gtasks-md` to access their Google Tasks account.

*   **Source Code Analysis:**
    1.  **`app/__main__.py:reconcile` function:** Fetches task lists, parses Markdown, creates backup, and calls `service.reconcile`.
    2.  **`app/googleapi.py:GoogleApiService.reconcile` function:**
        *   `gen_tasklist_ops()` generates DELETE operations for existing task lists if their titles are not found in new task lists from Markdown.
        *   `apply_task_list_op()` executes DELETE operations, calling `self.task_lists().delete()`.
        *   **Vulnerability Visualization:**
            *   **Normal Scenario:** Old Task Lists: ["Personal", "Work"], New Task Lists: ["Personal", "Work (modified)"] -> Operations: "Personal": UPDATE, "Work": UPDATE.
            *   **Malicious Scenario:** Old Task Lists: ["Personal", "Work"], New Task Lists: ["Malicious Title"] -> Operations: "Personal": DELETE, "Work": DELETE, "Malicious Title": INSERT.
    3.  The reconciliation logic incorrectly marks existing task lists for deletion when new Markdown contains different task list titles.

*   **Security Test Case:**
    1.  **Pre-Setup:** Install and configure `gtasks-md`. Create "Test List 1" and "Test List 2" with tasks in Google Tasks.
    2.  **Craft Malicious Markdown File (`malicious_tasks.md`):**
        ```markdown
        # TODO

        ## Malicious Task List Title
        ```
    3.  **Execute `reconcile`:** `gtasks-md reconcile malicious_tasks.md`.
    4.  **Verify Task Deletion:** Check Google Tasks; "Test List 1" and "Test List 2" should be deleted.

### Task Deletion via Title Manipulation in Reconciliation

*   **Vulnerability Name:** Task Deletion via Title Manipulation in Reconciliation

*   **Description:**
    1.  An attacker crafts a malicious Markdown file with task titles subtly different (e.g., extra spaces, casing) from existing Google Tasks titles.
    2.  The user is tricked into using `gtasks-md reconcile` with this file.
    3.  During reconciliation in `app/googleapi.py`, task matching is based on titles.
    4.  Subtle title differences cause incorrect matching; some existing tasks are not matched.
    5.  Unmatched tasks are interpreted as deletions and removed from Google Tasks.

*   **Impact:** Unintentional deletion of user's Google Tasks data. Attackers can cause significant data loss by crafting Markdown files leading to task deletion during reconciliation.

*   **Vulnerability Rank:** High

*   **Currently Implemented Mitigations:** None

*   **Missing Mitigations:**
    *   Implement exact title matching or offer different matching strategies.
    *   Confirmation step before deleting tasks, especially for large deletions.
    *   Diff view of changes before reconciliation for user review.

*   **Preconditions:**
    *   Attacker tricks user into using malicious Markdown with `gtasks-md reconcile`.
    *   Attacker knows some victim's task titles to craft malicious Markdown effectively.

*   **Source Code Analysis:**
    1.  **`app/googleapi.py` - `reconcile` function:** Synchronizes Markdown and Google Tasks using reconcile operations.
    2.  **`app/googleapi.py` - `gen_task_ops` function:**
        ```python
        def gen_task_ops(old_tasks: list[Task], new_tasks: list[Task]):
            task_to_op = {}
            for task in old_tasks:
                task_to_op[task.title] = (ReconcileOp.DELETE, task)

            for i, task in enumerate(new_tasks):
                if task.title in task_to_op: # Vulnerable title matching
                    task_to_op[task.title] = (
                        ReconcileOp.UPDATE,
                        task_to_op[task.title][1],
                        task,
                        i,
                    )
                else:
                    task_to_op[task.title] = (ReconcileOp.INSERT, task, i)

            return list(task_to_op.values())
        ```
        - Task matching in `gen_task_ops` relies on simple `task.title in task_to_op` string comparison.
        - Slight title variations (spaces, casing) lead to mismatch and incorrect deletion identification.
    3.  **`app/googleapi.py` - `apply_task_ops` function:** Executes DELETE operations, removing tasks from Google Tasks based on `gen_task_ops` output.

*   **Security Test Case:**
    1.  **Pre-test setup:** User has `gtasks-md` and "My Tasks" list with "Task to Keep" and "Task to Maybe Delete " (with space).
    2.  **Attacker's actions:** Malicious `malicious_tasks.md`:
        ```markdown
        # TODO

        ## My Tasks

        1.  [ ] Task to Keep
        1.  [ ] Task New
        ```
    3.  **User's actions:** `gtasks-md reconcile malicious_tasks.md --user default`.
    4.  **Verification:** Check "My Tasks" in Google Tasks; "Task to Maybe Delete " should be deleted due to title mismatch caused by extra space.