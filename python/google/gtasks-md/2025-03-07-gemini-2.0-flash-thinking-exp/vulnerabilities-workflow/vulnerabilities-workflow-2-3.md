- Vulnerability Name: Task Deletion Vulnerability via Malicious Markdown Injection

- Description:
    A malicious user can craft a Markdown file that, when processed by the `reconcile` command, causes the deletion of all tasks and task lists in the user's Google Tasks account. This is achieved by exploiting the title-based matching logic in the `reconcile` function and injecting a specially crafted task list title in the malicious Markdown file. When the `reconcile` function compares the old task lists (fetched from Google Tasks) with the new task lists (parsed from the malicious Markdown), it identifies all existing task lists as "to be deleted" because their titles do not match the injected malicious title.

    Steps to trigger the vulnerability:
    1. The attacker crafts a malicious Markdown file. This file contains a task list with a title that is different from any of the user's existing task list titles in Google Tasks. For example, the malicious file could contain only:
       ```markdown
       # TODO

       ## Malicious Task List Title
       ```
    2. The victim user, tricked by the attacker, executes the `reconcile` command using the malicious Markdown file:
       ```console
       gtasks-md reconcile malicious_tasks.md
       ```
    3. The `reconcile` command fetches the current task lists from the user's Google Tasks account.
    4. The command parses the `malicious_tasks.md` file, creating a new list of task lists based on the malicious content.
    5. The `reconcile` function in `app/googleapi.py` compares the old task lists (from Google) and the new task lists (from the malicious file). Since the malicious Markdown file contains a task list with a title "Malicious Task List Title" which is different from any existing task list title, all original task lists are marked for deletion.
    6. The `reconcile` function then proceeds to delete all task lists and consequently all tasks within them from the user's Google Tasks account, as it believes they are no longer present in the "new" Markdown state.

- Impact:
    Critical data loss. All tasks and task lists in the user's Google Tasks account are permanently deleted. This can lead to significant disruption and loss of important personal or professional task management data.

- Vulnerability Rank: Critical

- Currently Implemented Mitigations:
    None. The application currently lacks any input validation or sanitization of the Markdown content, and the reconciliation logic relies solely on title matching without any safeguards against malicious title manipulation.

- Missing Mitigations:
    - Input validation and sanitization for task list and task titles to prevent injection of malicious titles.
    - Confirmation step before deleting task lists or tasks, especially when a large number of deletions are about to occur.
    - Backup mechanism before reconciliation to allow easy restoration in case of unintended changes. (Note: Backup is implemented, but it is written *after* fetching current tasks, but *before* reconcile operation, so it can be used as mitigation).
    - More robust reconciliation logic that does not solely rely on title matching. Consider using task IDs or other unique identifiers if available, or implement a more sophisticated diffing algorithm.
    - User warning about the potential risks of using `reconcile` with untrusted Markdown files.

- Preconditions:
    - The attacker needs to trick the user into using a maliciously crafted Markdown file with the `reconcile` command.
    - The user must have authorized `gtasks-md` to access their Google Tasks account.

- Source Code Analysis:
    1. **`app/__main__.py:reconcile` function:**
       - Fetches existing task lists using `fetch_task_lists(service)`.
       - Parses the provided Markdown file using `markdown_to_task_lists(new_text)`.
       - Calls `backup.write_backup(old_text)` to create a backup of the old Markdown representation.
       - Executes the reconciliation logic using `asyncio.run(service.reconcile(old_task_lists, new_task_lists))`.

    2. **`app/googleapi.py:GoogleApiService.reconcile` function:**
       - `gen_tasklist_ops()` function generates a list of operations (DELETE, INSERT, UPDATE) for task lists by comparing old and new task lists based on their titles.
       - For each old task list, it's initially marked for deletion (`ReconcileOp.DELETE`).
       - Then, it iterates through new task lists. If a new task list title matches an old task list title, the operation is changed to `ReconcileOp.UPDATE`. If a new task list title does not match any old task list title, it's marked for insertion (`ReconcileOp.INSERT`).  Crucially, if a title from an old task list is *not* found in the new task lists, it remains marked for `DELETE`.
       - `apply_task_list_op()` function executes the operations. For `ReconcileOp.DELETE`, it calls `self.task_lists().delete(tasklist=task_list.id).execute()`.

    **Vulnerability Visualization:**

    Imagine the user has task lists "Personal" and "Work".

    **Normal Scenario (`reconcile` with a valid file):**
    - **Old Task Lists (from Google):** ["Personal", "Work"]
    - **New Task Lists (from Markdown):** ["Personal", "Work (modified)"]
    - `gen_tasklist_ops()` will produce:
        - "Personal": UPDATE
        - "Work": UPDATE

    **Malicious Scenario (`reconcile` with a malicious file):**
    - **Old Task Lists (from Google):** ["Personal", "Work"]
    - **New Task Lists (from Malicious Markdown):** ["Malicious Title"]
    - `gen_tasklist_ops()` will produce:
        - "Personal": DELETE
        - "Work": DELETE
        - "Malicious Title": INSERT

    - `apply_task_list_op()` will then delete "Personal" and "Work" task lists from Google Tasks because they are marked as `ReconcileOp.DELETE`.

- Security Test Case:
    1. **Pre-Setup:**
        - Ensure you have `gtasks-md` installed and configured with your Google Account.
        - Create at least two task lists in your Google Tasks account, for example, "Test List 1" and "Test List 2", each containing a few tasks.
        - Backup your current tasks using Google Tasks UI or another method if you are concerned about data loss during testing.

    2. **Craft Malicious Markdown File:**
        - Create a new Markdown file named `malicious_tasks.md` with the following content:
          ```markdown
          # TODO

          ## Malicious Task List Title
          ```
        - Note that "Malicious Task List Title" is different from your existing task list titles ("Test List 1" and "Test List 2").

    3. **Execute `reconcile` command with the malicious file:**
        ```console
        gtasks-md reconcile malicious_tasks.md
        ```
        - Replace `malicious_tasks.md` with the actual path to your malicious Markdown file if needed.

    4. **Verify Task Deletion:**
        - After the command execution, check your Google Tasks account (using the web UI or mobile app).
        - Observe that the task lists "Test List 1" and "Test List 2", along with all tasks within them, have been deleted.
        - Only a new task list titled "Malicious Task List Title" (which is empty) might be created if the reconciliation logic proceeds to insert new task lists after deleting the old ones (depending on the exact implementation details).

This test case confirms that a malicious Markdown file can indeed cause unintended deletion of task lists and tasks due to the vulnerability in the reconciliation logic.