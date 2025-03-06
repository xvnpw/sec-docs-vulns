- Vulnerability Name: Potential Cache Inconsistency due to Prefix Normalization
- Description:
    - The plugin normalizes S3 prefixes when storing Access Grants credentials in the cache. Specifically, in the `_process_matched_target` function within `aws_s3_access_grants_boto3_plugin/cache/access_grants_cache.py`, it removes the trailing "/*" from a `matchedGrantTarget`.
    - This normalization aims to handle grants defined at the prefix level (e.g., `s3://bucket/prefix/*`).
    - However, there's a potential for inconsistency in how S3 prefixes are handled during cache lookups, especially when object keys in subsequent requests contain variations like double slashes (`//`) or dot slashes (`/.//`).
    - Step-by-step scenario to trigger the vulnerability:
        1. An attacker has legitimate access to S3 bucket and prefix covered by an Access Grant defined as `s3://bucket/prefix/*`.
        2. The attacker makes an initial request (e.g., `GetObject`) to an object within the granted prefix, like `s3://bucket/prefix/object1.txt`.
        3. The plugin correctly retrieves Access Grants credentials and caches them, likely under the normalized prefix `s3://bucket/prefix`.
        4. The attacker then crafts a subsequent request to an object with a slightly altered prefix, for example, `s3://bucket/prefix//object2.txt` (using a double slash).
        5. Due to potential inconsistencies in prefix handling within the cache lookup mechanism, the plugin might fail to recognize this request as being covered by the previously cached credentials.
        6. This could lead to a cache miss, causing the plugin to bypass the cache and potentially re-evaluate Access Grants or, in some configurations, fall back to default credentials unnecessarily.
- Impact:
    - Performance degradation: Cache misses lead to repeated calls to the Access Grants service, increasing latency and potentially AWS service costs.
    - Unexpected Fallback Behavior: In configurations where fallback is enabled, cache misses might trigger unintended fallback to default S3 client credentials, even when Access Grants should be applicable. This could lead to inconsistent access control behavior.
- Vulnerability Rank: Medium
- Currently Implemented Mitigations:
    - Caching of Access Grants credentials in `aws_s3_access_grants_boto3_plugin/cache/access_grants_cache.py`.
    - Caching of Access Denied responses in `aws_s3_access_grants_boto3_plugin/cache/access_denied_cache.py`.
    - Prefix normalization in `aws_s3_access_grants_boto3_plugin/cache/access_grants_cache.py` using `_process_matched_target`.
- Missing Mitigations:
    - Robust prefix normalization during cache key construction for both storing and retrieving credentials. This should ensure consistent handling of prefixes with variations like double slashes, dot slashes, and trailing slashes.
    - Comprehensive security test cases specifically designed to validate cache behavior with different prefix formats and ensure cache hits as expected, even with minor variations in object keys.
- Preconditions:
    - The aws-s3-access-grants-boto3-plugin is installed and registered with a boto3 S3 client.
    - Caching mechanisms within the plugin are active (default behavior).
    - An Access Grant is configured for a prefix at the S3 bucket (e.g., `s3://bucket/prefix/*`).
- Source Code Analysis:
    - `aws_s3_access_grants_boto3_plugin/cache/access_grants_cache.py`:
        - `_process_matched_target(matched_grant_target)`: This function normalizes the `matchedGrantTarget` by removing trailing "/*", potentially leading to a normalized prefix in the cache (lines 101-104).
        - `get_credentials(s3_control_client, cache_key, account_id, access_denied_cache)`: This function handles cache lookups and service calls. It uses `_search_credentials_at_prefix_level` and `_search_credentials_at_character_level` for cache retrieval (lines 111-132).
        - `_search_credentials_at_prefix_level(cache_key)`: This function iteratively shortens the `s3_prefix` in the `cache_key` for cache lookups, potentially with different prefix normalization compared to how prefixes are stored (lines 50-58).
    - `aws_s3_access_grants_boto3_plugin/s3_access_grants_plugin.py`:
        - `_get_s3_prefix(operation_name, request)`: This function constructs the `s3_prefix` from the incoming request parameters. The way it handles different S3 operations and extracts prefixes needs to be consistent with cache key construction.
- Security Test Case:
    1. **Setup Access Grant:** In an AWS account with S3 Access Grants enabled, create an Access Grant for `s3://<your_registered_bucket_name>/testprefix/*` with `READ` permission, granting access to the IAM role being used for testing. Replace `<your_registered_bucket_name>` with a bucket you control and have registered as an Access Grants location.
    2. **Initialize S3 Client with Plugin:**
       ```python
       import botocore.session
       from aws_s3_access_grants_boto3_plugin.s3_access_grants_plugin import S3AccessGrantsPlugin

       session = botocore.session.get_session()
       s3_client = session.create_client('s3')
       plugin = S3AccessGrantsPlugin(s3_client, fallback_enabled=False) # fallback disabled to clearly see Access Grant issues
       plugin.register()
       ```
    3. **Initial Request (Cache Population):**
       ```python
       bucket_name = "<your_registered_bucket_name>" # Use the same bucket name as in step 1
       key_object1 = "testprefix/object1.txt"
       try:
           response = s3_client.get_object(Bucket=bucket_name, Key=key_object1)
           print(f"GetObject {key_object1} - Success: {response['ResponseMetadata']['HTTPStatusCode']}")
       except Exception as e:
           print(f"GetObject {key_object1} - Error: {e}")
           raise
       ```
    4. **Subsequent Request with Double Slash (Potential Cache Miss):**
       ```python
       key_object2 = "testprefix//object2.txt" # Double slash in the key
       try:
           response = s3_client.get_object(Bucket=bucket_name, Key=key_object2)
           print(f"GetObject {key_object2} - Success: {response['ResponseMetadata']['HTTPStatusCode']}")
       except Exception as e:
           # Check if the error indicates Access Denied unexpectedly, which might suggest a cache miss leading to incorrect authorization.
           print(f"GetObject {key_object2} - Error: {e}")
           print(f"Error details: {e}")
       ```
    5. **Analyze Results:**
        - Examine the output of both `GetObject` calls.
        - If both requests succeed with HTTP status 200, the cache might be working correctly in this specific scenario.
        - **To confirm cache behavior more thoroughly, you would need to add logging or debugging to the `AccessGrantsCache` class to track cache hits and misses.**  Ideally, after the first successful request (`object1.txt`), the second request (`object2.txt`) should be a cache hit. If the second request triggers a new call to the Access Grants service (which you could observe through logging or network monitoring if available in your testing environment), it would indicate a cache miss and the potential vulnerability.
    6. **Repeat with other prefix variations:** Test with keys like `"testprefix/.//object3.txt"`, `"testprefix/./object4.txt"` and other variations to explore the robustness of prefix normalization and cache lookup.