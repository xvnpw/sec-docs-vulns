- Vulnerability name: ElasticSearch Injection in `in-video-search` and `archive-video-search` services
- Description:
    - An attacker can inject malicious ElasticSearch queries through the `q` parameter in the `/` endpoint of the `in-video-search` and `archive-video-search` services.
    - The application directly uses user-provided input from the `q` parameter to construct ElasticSearch queries without proper sanitization.
    - Step 1: Attacker crafts a malicious ElasticSearch query payload.
    - Step 2: Attacker sends an HTTP GET request to either `/` endpoint of `in-video-search` or `archive-video-search` service, including the malicious payload in the `q` parameter. For example: `https://<service-url>/?urlId=<valid_urlId>&q=<elasticsearch_injection_payload>`.
    - Step 3: The vulnerable service receives the request and incorporates the unsanitized `q` parameter directly into the ElasticSearch query.
    - Step 4: The ElasticSearch backend executes the injected query.
    - Step 5: The attacker may receive sensitive information, modify data, or cause other unintended actions depending on the injected payload and ElasticSearch configuration.
- Impact:
    - Data Breaches: An attacker could potentially extract sensitive data from the ElasticSearch index by crafting queries to bypass intended data access restrictions.
    - Data Manipulation: Depending on the ElasticSearch configuration and permissions, an attacker might be able to modify or delete data within the index.
    - Unauthorized Access: An attacker might be able to bypass intended search logic and access data they are not supposed to see.
    - Service Disruption: Injected queries could be crafted to overload or crash the ElasticSearch service, leading to denial of service.
- Vulnerability rank: High
- Currently implemented mitigations:
    - None. The code in `/code/in-video-search/main.py` and `/code/archive-video-search/main.py` directly uses the `q` parameter from the request within the ElasticSearch query without any sanitization or validation.
- Missing mitigations:
    - Input Sanitization: Sanitize user input in the `q` parameter to remove or escape characters that have special meaning in ElasticSearch query syntax.
    - Parameterized Queries: Utilize parameterized queries or an ElasticSearch query builder library that automatically handles input escaping and prevents injection. This would ensure that user input is treated as data, not as part of the query structure.
    - Input Validation: Implement validation on the `q` parameter to ensure it conforms to expected patterns and reject requests with unexpected or potentially malicious input.
- Preconditions:
    - The `in-video-search` or `archive-video-search` service must be deployed and publicly accessible.
    - A vulnerable ElasticSearch instance must be configured and accessible to these services.
- Source code analysis:
    - File: `/code/in-video-search/main.py`
        ```python
        @app.route("/")
        def main():
            q = request.args.get("q")
            urlId = request.args.get("urlId")
            orgId = request.args.get("orgId")

            # ... Elasticsearch client initialization ...

            queryBody = {
                "query": {
                    "bool": {
                        "should": {
                            "match": {
                                "transcriptStr": {
                                    "query": q, # Vulnerable code: User input 'q' is directly injected into the ElasticSearch query.
                                    "operator": "and"
                                }
                            },
                        },
                        "must": [
                            { "match": { "urlIdentifier": urlId } }
                        ]
                    }
                },
                # ...
            }

            searchObj = searchClient.search(
                index = orgId,
                body = queryBody
            )
            # ...
        ```
    - File: `/code/archive-video-search/main.py`
        ```python
        @app.route("/")
        def main():
            q = request.args.get("q")
            orgId = request.args.get("orgId")

            # ... Elasticsearch client initialization ...

            queryBody = {
                "query": {
                    "bool": {
                        "should": {
                            "match": {
                                "transcriptStr": {
                                    "query": q, # Vulnerable code: User input 'q' is directly injected into the ElasticSearch query.
                                    "operator": "and"
                                }
                            }
                        }
                    }
                },
                # ...
            }

            searchObj = searchClient.search(
                index = orgId,
                body = queryBody
            )
            # ...
        ```
    - Visualization:
        ```
        [User Input (q parameter)] --> [in-video-search/archive-video-search Service] --> [Unsanitized Input in ElasticSearch Query] --> [ElasticSearch Backend] --> [Potential Injection Exploit]
        ```
- Security test case:
    - Step 1: Deploy the `in-video-search` or `archive-video-search` service and ensure it is publicly accessible.
    - Step 2: Identify a valid `urlId` for the `in-video-search` service or a valid `orgId` for the `archive-video-search` service.
    - Step 3: Craft a malicious ElasticSearch query payload. For example, to test for basic injection, use a payload that should always return results, such as `* OR 1==1`. A more specific payload to test for information disclosure could be `* OR _exists_:meetingDate`.
    - Step 4: Send an HTTP GET request to the vulnerable service with the crafted payload in the `q` parameter.
        - For `in-video-search`: `https://<your-in-video-search-service-url>/?urlId=<valid_urlId>&q=* OR 1==1`
        - For `archive-video-search`: `https://<your-archive-video-search-service-url>/?orgId=<valid_orgId>&q=* OR 1==1`
    - Step 5: Analyze the response.
        - If the vulnerability is present, the search results might include entries that should not normally match the intended search query (e.g., if you used `* OR 1==1`, you might get all or many entries).
        - Examine the response for any error messages from ElasticSearch, which might indicate successful injection or attempts.
        - In a real-world scenario, a more sophisticated attacker would use tools like Burp Suite to intercept and modify requests to fine-tune their injection payloads and observe the backend responses for more detailed exploitation.