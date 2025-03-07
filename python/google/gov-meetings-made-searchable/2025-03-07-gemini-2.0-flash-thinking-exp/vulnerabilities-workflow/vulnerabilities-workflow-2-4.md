### Vulnerability List

- Vulnerability Name: ElasticSearch Injection
- Description:
    1. An attacker can send a crafted HTTP GET request to either the `/` endpoint of the `in-video-search` or `archive-video-search` App Engine services.
    2. This request includes a malicious payload within the `q` parameter, which is intended for search queries.
    3. The `main.py` files of both services (`in-video-search` and `archive-video-search`) directly embed the value of the `q` parameter into the body of an ElasticSearch query.
    4. Because the input is not sanitized or parameterized, the attacker's malicious payload is interpreted as part of the ElasticSearch query itself.
    5. This allows the attacker to manipulate the ElasticSearch query beyond the intended search functionality.
- Impact:
    - An attacker could potentially bypass intended search restrictions and access sensitive data stored in the ElasticSearch index, including transcripts of government meetings.
    - Depending on the ElasticSearch configuration and permissions, an attacker might be able to modify or delete data within the index.
    - In a worst-case scenario, if ElasticSearch is misconfigured or running with elevated privileges, an attacker could potentially gain code execution on the ElasticSearch server itself, although this is less likely in a managed cloud environment.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - None. The code directly uses user input in ElasticSearch queries without any sanitization or parameterization.
- Missing Mitigations:
    - Input Sanitization: Implement robust input sanitization and validation for the `q` parameter in both `in-video-search/main.py` and `archive-video-search/main.py`. This should include stripping potentially malicious characters or patterns and validating the input against an expected format.
    - Parameterized Queries: Use ElasticSearch's parameterized query functionality to separate the query structure from user-provided data. This prevents user input from being interpreted as query commands.
    - Principle of Least Privilege: Ensure that the credentials used by the `in-video-search` and `archive-video-search` services to access ElasticSearch have the minimum necessary permissions. Avoid granting write or delete permissions if read-only access is sufficient for the intended search functionality.
- Preconditions:
    - The `in-video-search` or `archive-video-search` App Engine services must be deployed and publicly accessible.
    - An ElasticSearch instance must be configured and running, and accessible to these services.
- Source Code Analysis:
    - File: `/code/in-video-search/main.py`
        ```python
        queryBody = {
            "query": {
                "bool": {
                    "should": {
                        "match": {
                            "transcriptStr": {
                                "query": q,  # Vulnerable: User input 'q' is directly embedded in the query
                                "operator": "and"
                            }
                        },
                    },
                    "must": [
                        { "match": { "urlIdentifier": urlId } }
                    ]
                }
            },
            ...
        }

        searchObj = searchClient.search(
            index = orgId,
            body = queryBody
        )
        ```
        The `q` variable, which takes its value directly from the `request.args.get("q")`, is used without any sanitization within the `query` part of the `queryBody` dictionary. This dictionary is then passed as the `body` to the `searchClient.search()` function, which executes the ElasticSearch query. An attacker can manipulate the `q` parameter to inject arbitrary ElasticSearch queries.

    - File: `/code/archive-video-search/main.py`
        ```python
        queryBody = {
            "query": {
                "bool": {
                    "should": {
                        "match": {
                            "transcriptStr": {
                                "query": q, # Vulnerable: User input 'q' is directly embedded in the query
                                "operator": "and"
                            }
                        }
                    }
                },
                ...
            }
        },
        ...
    }

    searchObj = searchClient.search(
        index = orgId,
        body = queryBody
    )
        ```
        Similar to `in-video-search/main.py`, the `archive-video-search/main.py` also directly uses the unsanitized `q` parameter from the request to build the ElasticSearch query, making it vulnerable to ElasticSearch injection.

- Security Test Case:
    1. Deploy the `app-engine-front-end`, `in-video-search`, and `archive-video-search` services to Google App Engine. Ensure that the ElasticSearch instance is running and accessible to these services.
    2. Identify the public URL for the `app-engine-front-end` service.
    3. Access the `/ep-searchVideo` endpoint of the `app-engine-front-end` service through a web browser or using `curl`. This endpoint proxies requests to the `in-video-search` service. To trigger the vulnerability in `in-video-search`, you need to call `/ep-searchVideo`. For `archive-video-search`, you need to call `/ep-searchArchive`.
    4. Construct a malicious query string for the `q` parameter. For example, to test for basic injection, you can try to use ElasticSearch's wildcard query. Assuming you know the `urlId` and `orgId` of a meeting, craft a URL like this, replacing placeholders with actual values:
        ```
        https://<app-engine-front-end-url>/ep-searchVideo?urlId=<valid_urlId>&orgId=<valid_orgId>&q=OR%20_exists_:%20field
        ```
        or for `archive-video-search`:
        ```
        https://<app-engine-front-end-url>/ep-searchArchive?orgId=<valid_orgId>&q=OR%20_exists_:%20field
        ```
        In these example URLs, `q=OR%20_exists_:%20field` is a malicious payload. `%20` represents a space character in URL encoding, and `OR _exists_: field` is an attempt to inject an `exists` query using the `OR` operator which might not be intended as a valid user search term, but rather as an ElasticSearch query clause. Replace `field` with a known field in your ElasticSearch index, like `meetingDate` or `transcriptStr`.
    5. Send the crafted URL request.
    6. Analyze the response. If the application returns results that are broader than expected or error messages from ElasticSearch that indicate the injected query was parsed and executed by ElasticSearch, it confirms the ElasticSearch injection vulnerability. For instance, if you use `_exists_:meetingDate` and get results for all meetings regardless of the original search term, it's a sign of successful injection.
    7. For further testing, try more complex ElasticSearch query injections to attempt to extract specific data or manipulate search behavior in unintended ways. Note that the success of specific injection payloads will depend on the ElasticSearch version, configuration, and the data indexed.