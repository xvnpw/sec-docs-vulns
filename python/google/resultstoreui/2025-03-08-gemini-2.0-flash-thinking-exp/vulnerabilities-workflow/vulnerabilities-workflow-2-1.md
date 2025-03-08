- vulnerability name: Search Query Injection in SearchInvocations

- description:
  - A malicious user can inject arbitrary search queries into the ResultStore search bar.
  - The user input from the search bar is passed to the `SearchInvocations` gRPC method in the backend proxy server.
  - The proxy server directly forwards this query to the ResultStore API without proper sanitization or validation.
  - By crafting a malicious search query, an attacker might be able to bypass access controls or extract sensitive data from ResultStore if the backend ResultStore API is vulnerable to query injection and input sanitization is insufficient on the ResultStore API side as well.

- impact:
  - Unauthorized access to sensitive test result data stored in Google Cloud ResultStore.
  - Potential bypass of access control mechanisms, allowing unauthorized users to view results they should not have access to.
  - Information disclosure of confidential test results or project metadata.

- vulnerability rank: High

- currently implemented mitigations:
  - None in the provided proxy server code.
  - There might be mitigations in the client-side code (not provided) or in the backend ResultStore API (out of scope).

- missing mitigations:
  - Input sanitization and validation on the server-side proxy before forwarding the search query to the ResultStore API.
  - Implement proper output encoding when displaying search results to prevent injection vulnerabilities in the UI.
  - Consider using parameterized queries or prepared statements if constructing queries dynamically to the backend ResultStore API to prevent injection.

- preconditions:
  - Attacker has network access to the Resultstore Search application.
  - The application is configured to forward search queries directly to the backend ResultStore API without sanitization.
  - The backend ResultStore API is vulnerable to search query injection or does not perform sufficient input validation.

- source code analysis:
  - File: `/code/resultstoresearch/server/resultstoresearch/resultstore_proxy_server.py`
  - Method: `SearchInvocations`
  ```python
    def SearchInvocations(self, request, context):
        """
        Proxies the SearchInvocations gRPC call forward

        Args:
            request (SearchInvocationsRequest): The search request
            context (grpc.Context)

        Returns:
            SearchInvocationsResponse
        """
        _LOGGER.info('Received request: %s', request)
        new_request = resultstore_download_pb2.SearchInvocationsRequest(
            query=request.query, # User-controlled input 'request.query' is directly used here
            project_id=request.project_id,
            page_size=request.page_token,
        )
        return self._search_helper(new_request, request.tool, context)

    def _search_helper(self, request, tool, context):
        metadata = context.invocation_metadata()
        stub = resultstore_download_pb2_grpc.ResultStoreDownloadStub(
            self.channel)
        try:
            response = stub.SearchInvocations(request, metadata=metadata) # 'request' which contains user input 'request.query' is passed directly to backend API
        except grpc.RpcError as rpc_error:
            _LOGGER.error('Received error: %s', rpc_error)
            configure_grpc_error(context, rpc_error)
            return resultstoresearch_download_pb2.SearchInvocationsResponse()
        else:
            _LOGGER.info('Received message: %s', response)
            tools_list = self.fs.get_tools()
            tools_list = update_tools_list(response.invocations, tools_list,
                                           self.fs)
            filtered_invocations = filter_tool(response.invocations, tool)
            return resultstoresearch_download_pb2.SearchInvocationsResponse(
                invocations=filtered_invocations,
                next_page_token=response.next_page_token,
                tools_list=list(tools_list))
  ```
  - Visualization:
  ```
  User Input (Search Bar) --> SearchInvocations (proxy server) --> SearchInvocationsRequest (gRPC) --> ResultStore API
  ```

- security test case:
  - Preconditions:
    - Deploy a publicly accessible instance of the Resultstore Search application.
  - Steps:
    1. Open a web browser and navigate to the deployed Resultstore Search application.
    2. In the search bar, enter a malicious search query designed to test for injection, for example: `name="test-invocation" OR 1=1 --` or `labels:"' or '1'='1"` or similar SQL/NoSQL injection payloads adapted for search queries.
    3. Observe the application's response.
    4. Analyze the search results. If the query injection is successful, the application might return unexpected results, bypass access controls, or reveal sensitive information.
  - Expected result:
    - If the vulnerability exists, the application will process the malicious query and potentially return unexpected results or errors, indicating a successful injection.
    - A secure application should sanitize the input and either return no results or an error indicating an invalid query, without revealing internal data or bypassing access controls.
  - Success condition:
    - The test is successful if the application returns unexpected search results or errors due to the injected query, indicating a search query injection vulnerability.