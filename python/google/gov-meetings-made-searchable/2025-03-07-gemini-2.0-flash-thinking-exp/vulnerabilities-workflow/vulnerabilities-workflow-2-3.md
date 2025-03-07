### Vulnerability List:

* Vulnerability Name: Elasticsearch Query Injection
* Description:
    1. An attacker sends a crafted HTTP GET request to the `/` endpoint of the `in-video-search` or `/` endpoint of the `archive-video-search` service.
    2. The request includes malicious Elasticsearch query syntax within the `q` parameter. For example, using Elasticsearch DSL to manipulate the query logic.
    3. The `main.py` in both services extracts the `q` parameter value without sanitization.
    4. This unsanitized value is directly embedded into the `query` field of an Elasticsearch `match` query in the `queryBody`.
    5. The `searchClient.search()` function executes this crafted Elasticsearch query against the backend Elasticsearch instance.
    6. If the malicious payload is crafted correctly, the attacker can manipulate the Elasticsearch query to bypass intended search logic, extract sensitive data, or potentially perform other malicious actions within the Elasticsearch instance depending on the Elasticsearch configuration and permissions.
* Impact:
    - **Data Breach:** Attackers could potentially bypass intended search restrictions and retrieve sensitive information from the Elasticsearch index, including transcripts of government meetings which may contain personal or confidential data.
    - **Data Manipulation:** Depending on Elasticsearch configuration, attackers might be able to modify or delete data within the Elasticsearch index.
    - **Unauthorized Access:** Attackers could potentially gain unauthorized access to information beyond what is intended for public access.
    - **Service Disruption:** While not a denial of service vulnerability in itself, successful query injection might lead to unexpected Elasticsearch behavior or errors, potentially disrupting the search service.
* Vulnerability Rank: High
* Currently Implemented Mitigations:
    - None. The code directly embeds user input into Elasticsearch queries without any sanitization or validation.
* Missing Mitigations:
    - **Input Sanitization:** Implement robust input sanitization on the `q` parameter in both `in-video-search/main.py` and `archive-video-search/main.py`. Sanitize or escape special characters and Elasticsearch operators to prevent them from being interpreted as part of the query structure. Consider using a query builder library to construct queries programmatically instead of string interpolation.
    - **Input Validation:** Implement validation on the `q` parameter to ensure it conforms to expected input types and lengths.
    - **Principle of Least Privilege:** Ensure that the Elasticsearch user credentials used by the `in-video-search` and `archive-video-search` services have the minimum necessary permissions. Restrict write or delete permissions if not absolutely required.
    - **Web Application Firewall (WAF):** Deploy a WAF in front of the application to detect and block common injection attempts.
* Preconditions:
    - A publicly accessible instance of the `in-video-search` or `archive-video-search` service must be deployed.
    - An Elasticsearch instance must be configured as the backend for these services and must contain indexed meeting transcript data.
* Source Code Analysis:
    - **File: /code/in-video-search/main.py**
        ```python
        @app.route("/")
        def main():
            q = request.args.get("q") # User-supplied query parameter 'q' is retrieved
            urlId = request.args.get("urlId")
            orgId = request.args.get("orgId")

            searchClient = Elasticsearch( # Elasticsearch client initialization
                ["__Elastic_Search_Instance_URL__"],
                http_auth = (
                    "__Elastic_Search_Instance_Username__",
                    "__Elastic_Search_Instance_Password__"
                )
            )

            queryBody = { # Elasticsearch query body is constructed
                "query": {
                    "bool": {
                        "should": {
                            "match": {
                                "transcriptStr": {
                                    "query": q, # Unsanitized user input 'q' is directly inserted into the query
                                    "operator": "and"
                                }
                            },
                        },
                        "must": [
                            { "match": { "urlIdentifier": urlId } }
                        ]
                    }
                },
                "_source": ["mediaTimestamp", "meetingDate", "segmentLength"],
                "highlight": {
                    "fields" : {
                        "transcriptStr": {
                            "type": "plain",
                            "fragment_size": 38,
                            "number_of_fragments": 5
                        }
                    }
                },
                "size": 100,
                "min_score": 1.1
            }

            try:
                searchObj = searchClient.search( # Elasticsearch search is executed with the crafted query
                    index = orgId,
                    body = queryBody
                )
                outputStr = json.dumps(searchObj)
            except:
                outputStr = json.dumps( { "None": "None" } )

            return Response(outputStr, mimetype="application/json")
        ```
        **Visualization:**

        ```
        User Input (q) --> main() --> queryBody (unsanitized q) --> searchClient.search() --> Elasticsearch
        ```

    - **File: /code/archive-video-search/main.py**
        ```python
        @app.route("/")
        def main():
            q = request.args.get("q") # User-supplied query parameter 'q' is retrieved
            orgId = request.args.get("orgId")

            searchClient = Elasticsearch( # Elasticsearch client initialization
                ["__Elastic_Search_Instance_URL__"],
                http_auth = (
                    "__Elastic_Search_Instance_Username__",
                    "__Elastic_Search_Instance_Password__"
                )
            )
            queryBody = { # Elasticsearch query body is constructed
                "query": {
                    "bool": {
                        "should": {
                            "match": {
                                "transcriptStr": {
                                    "query": q, # Unsanitized user input 'q' is directly inserted into the query
                                    "operator": "and"
                                }
                            }
                        }
                    }
                },
                "sort": [
                    { "_score": { "order": "desc" } },
                ],
                "size": 0,
                "aggs": {
                    "group_by_meeting": {
                        "terms": {
                            "field": "globalId",
                            "size": 80,
                            "min_doc_count": 1
                        },
                        "aggs": {
                            "meeting_details": {
                                "top_hits": {
                                    "size": 1,
                                    "_source": {
                                        "includes": ["meetingDate", "meetingDesc", "urlIdentifier"]
                                    }
                                }
                            }
                        }
                    }
                }
            }

            try:
                searchObj = searchClient.search( # Elasticsearch search is executed with the crafted query
                    index = orgId,
                    body = queryBody
                )
                outputStr = json.dumps(searchObj)
            except:
                outputStr = json.dumps( { "None": "None" } )

            return Response(outputStr, mimetype="application/json")
        ```
        **Visualization:**

        ```
        User Input (q) --> main() --> queryBody (unsanitized q) --> searchClient.search() --> Elasticsearch
        ```

        In both services, the flow is identical in terms of vulnerability. User-provided input `q` is directly used to construct the Elasticsearch query without any form of sanitization, leading to the Elasticsearch Query Injection vulnerability.

* Security Test Case:
    1. Deploy the `in-video-search` service to a publicly accessible endpoint.
    2. Identify the URL for the deployed `in-video-search` service (e.g., `https://<your-service-url>.appspot.com`).
    3. Construct a malicious HTTP GET request to this URL. For example, to attempt to retrieve all documents in the index, you can inject Elasticsearch query syntax to bypass the intended `match` query. A sample malicious query could be `q=* OR urlIdentifier:your_url_id`. This attempts to use `OR` operator and wildcard `*` which might be interpreted by Elasticsearch depending on configuration. A more direct approach to bypass the `match` query would be to inject a different query type. For instance, to test for basic injection, try injecting `q=test) OR _exists_:field` where `field` is a field that is known to exist in the index.
    4. Send the crafted request using a tool like `curl` or a web browser. For example:
       ```bash
       curl "https://<your-service-url>.appspot.com/?urlId=your_url_id&orgId=your_org_id&q=test) OR _exists_:meetingDesc"
       ```
       Replace `<your-service-url>`, `your_url_id`, and `your_org_id` with the actual values for your deployed instance.
    5. Analyze the response. If the vulnerability is present, the response from the service will likely include search results that deviate from the intended behavior of searching for the term "test" within the specified `urlId`. For example, if the query injection is successful, you might see results that include all documents where the `meetingDesc` field exists, effectively bypassing the original search intent.
    6. Further refine the malicious query to test for more impactful injections, such as attempting to extract specific data or modify search behavior. For example, try injecting different Elasticsearch query types or operators to observe the system's response.
    7. Observe Elasticsearch logs (if accessible) to confirm the execution of the injected query and analyze any errors or unusual activity.