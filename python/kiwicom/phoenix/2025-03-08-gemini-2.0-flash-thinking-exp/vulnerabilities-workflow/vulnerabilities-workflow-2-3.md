### Vulnerability List

- Vulnerability Name: Insecure Direct Object Reference in `create_channel` view
- Description:
    1. An attacker without authorization to manage outages can access the `/slack/create_channel/<int:pk>` endpoint directly by crafting a POST request.
    2. The `create_channel` view, intended to be triggered via Slack interaction, does not properly validate user permissions before creating a dedicated Slack channel for an outage.
    3. By providing an outage `pk` in the URL, an unauthorized user can trigger the creation of a dedicated Slack channel for any outage, even if they are not an assignee or creator of that outage.
- Impact:
    - Unauthorized users can create Slack channels for outages they are not authorized to manage.
    - This can lead to confusion and potential information leakage, as unauthorized users might gain access to outage-related discussions in the newly created channel.
    - It violates the intended permission model where channel creation should be restricted to authorized users interacting with the outage management system via Slack commands.
- Vulnerability Rank: Medium
- Currently Implemented Mitigations:
    - None. The view function `phoenix/slackbot/views.py:create_channel` only checks for `user` in the request but does not validate permissions based on `user_can_modify_outage` for the given `pk` when accessed directly via POST request.
- Missing Mitigations:
    - Implement proper permission checks in the `create_channel` view to ensure only authorized users (creators or assignees) can create dedicated channels for specific outages.
    - Restrict direct POST access to this endpoint and ensure it's only triggered through authorized Slack interactions.
- Preconditions:
    - Attacker knows or can guess a valid `pk` of an existing outage.
    - The Phoenix application is publicly accessible or accessible to the attacker's network.
- Source Code Analysis:
    1. View function `create_channel` in `/code/phoenix/slackbot/views.py`:
    ```python
    @api_view(["POST"])
    def create_channel(request, pk):
        user = request.get("user") # [POINT 1] User information is retrieved but not fully utilized for authorization in direct POST request scenario
        if user:
            user_id = user.get("id")
            if user_id:
                if not user_can_modify_outage(user_id, pk): # [POINT 2] Permission check exists but is conditional on 'user' being available, which might not be the intended user in a direct POST call. Also, this check is performed AFTER announcement retrieval and channel name generation.
                    post_warning_to_user(
                        user_id=user_id,
                        text="*Buttons only usable by creator or assignees*",
                    )
                    return Response(status=status.HTTP_200_OK)
        announcement = Announcement.objects.get(outage_id=pk) # [POINT 3] Announcement is retrieved based on pk without prior authorization check.
        if not announcement.dedicated_channel_id:
            channel_id = create_channel_task(
                announcement.outage.id, announcement.dedicated_channel_name
            )
            data = {"id": channel_id, "name": announcement.dedicated_channel_name}
            return Response(data=data, status=status.HTTP_200_OK)
        return Response(status=status.HTTP_200_OK)
    ```
    - **Point 1**: The code retrieves user information from the request (`request.get("user")`). However, when accessing this view directly via a POST request (outside of Slack's interaction flow), the `request.user` context might not reliably represent the actual user attempting to create the channel, or it might be missing entirely if authentication is bypassed.
    - **Point 2**: The permission check `user_can_modify_outage(user_id, pk)` is present, but it's conditionally executed only if `user` and `user_id` are available. In a direct POST request, an attacker might manipulate or omit user-related headers, potentially bypassing this check. Even if `user` is available (e.g., through session authentication if enabled for API views), the authorization is checked *after* retrieving the `Announcement` object, which is an insecure direct object reference pattern.
    - **Point 3**: The `Announcement.objects.get(outage_id=pk)` line retrieves the announcement based on the `pk` directly from the URL, without any authorization check *before* object retrieval. This allows an attacker to reference any outage by its `pk` and attempt to create a channel.

- Security Test Case:
    1. Log in to the Phoenix application as a user who does *not* have "Can change outage" permission and is *not* a creator or assignee of a specific outage (Outage ID: 1, for example).
    2. Identify an existing Outage ID (e.g., 1) from the system (e.g., by browsing the outage list page if accessible, or guessing).
    3. Using `curl` or a similar tool, craft a POST request to the `/slack/create_channel/1` endpoint. Assume the application is running at `http://localhost:8000`.
    ```bash
    curl -X POST http://localhost:8000/slack/create_channel/1
    ```
    4. Observe the response. If the vulnerability exists, the response will be `200 OK` and might contain data about the created channel (depending on the exact state and code execution path).
    5. Check the Slack workspace. A new dedicated channel for Outage ID 1 should have been created, even though the user who initiated the request is not authorized to manage this outage.