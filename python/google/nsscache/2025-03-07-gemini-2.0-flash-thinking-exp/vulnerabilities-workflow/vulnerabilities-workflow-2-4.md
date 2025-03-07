- Vulnerability Name: LDAP Injection via Malicious Entries
- Description:
    1. An attacker compromises the remote LDAP server that `nsscache` synchronizes with.
    2. The attacker injects malicious user or group entries into the LDAP directory. For example, they could create a user entry with UID 0 or a group entry that grants excessive privileges.
    3. `nsscache`'s `update` command is executed, either manually or via cron job.
    4. `nsscache` connects to the compromised LDAP server and retrieves the malicious entries as part of the synchronization process.
    5. `nsscache` writes these malicious entries directly into the local NSS database files (e.g., `/etc/passwd.cache`, `/etc/group.cache`).
    6. Systems relying on `nsscache` and `libnss-cache` for user and group information now use the compromised NSS databases.
    7. An attacker can exploit these malicious entries for unauthorized access or privilege escalation, for instance, by logging in as the injected UID 0 user or leveraging membership in the malicious group.
- Impact: Privilege escalation, unauthorized access, and potential compromise of systems relying on `nsscache` for authentication and authorization.
- Vulnerability Rank: Critical
- Currently Implemented Mitigations: None in `nsscache` code. The security relies entirely on the security of the remote directory service.
- Missing Mitigations:
    - Input Validation: Implement validation of data retrieved from LDAP to ensure it conforms to expected formats and constraints (e.g., UID ranges, username character sets, group membership limitations).
    - Data Sanitization: Sanitize data retrieved from LDAP to prevent injection of malicious content into local NSS databases.
    - Anomaly Detection: Implement mechanisms to detect anomalies in the data retrieved from LDAP, such as unexpected UIDs or GIDs, or unusual usernames or group names, and trigger alerts or prevent synchronization in such cases.
- Preconditions:
    - A publicly accessible instance of `nsscache` is set up to synchronize with a remote LDAP server.
    - An attacker gains control of the remote LDAP server and can modify its data.
- Source Code Analysis:
    - In `nss_cache/sources/ldapsource.py`, methods like `GetPasswdMap`, `GetGroupMap`, and `GetShadowMap` directly map LDAP attributes to `MapEntry` attributes without validation. For example, in `PasswdUpdateGetter.Transform`, the UID and GID from LDAP are directly assigned to `PasswdMapEntry.uid` and `PasswdMapEntry.gid`.
    - In `nss_cache/caches/files.py`, methods like `FilesPasswdMapHandler._WriteData` directly write the `MapEntry` attributes to the cache files without sanitization.
- Security Test Case:
    1. Set up a test environment: Deploy `nsscache` in a test environment configured to use a mock LDAP server.
    2. Establish a baseline: Synchronize `nsscache` with the mock LDAP server containing legitimate user and group data. Verify that local NSS databases are correctly populated.
    3. Compromise the mock LDAP server: Modify the mock LDAP server to inject a malicious user entry. For example, create a user with username `malicious_user` and `uidNumber: 0`.
    4. Run `nsscache update`: Execute the `nsscache update` command to synchronize with the (now compromised) mock LDAP server.
    5. Verify malicious entry in local cache: Check the `/etc/passwd.cache` file (or equivalent based on configuration). Verify that the malicious user entry (`malicious_user` with UID 0) is present in the cache file.
    6. Attempt privilege escalation: (This step would be performed on a test system configured to use `libnss-cache` and the generated cache files). Try to login as `malicious_user` or exploit the injected UID 0 entry to gain elevated privileges on the test system.