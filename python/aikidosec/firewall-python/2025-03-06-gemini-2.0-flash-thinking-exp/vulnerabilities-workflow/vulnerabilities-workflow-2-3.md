- vulnerability name: Command Injection in Flask Sample App
  - description: The Flask sample app `/code/sample-apps/flask-mysql/app.py` has a `/shell` endpoint vulnerable to command injection due to unsanitized user input passed to `subprocess.run` with `shell=True`. An attacker can execute arbitrary commands on the server.
  - impact: High. Full system compromise, data exfiltration, denial of service.
  - vulnerability rank: high
  - currently implemented mitigations: None
  - missing mitigations: Input validation, parameterized command execution, Zen firewall protection for the endpoint.
  - preconditions: Flask sample app running and `/shell` endpoint accessible.
  - source code analysis: Vulnerable code in `/code/sample-apps/flask-mysql/app.py` at `/shell` endpoint using `subprocess.run(command, capture_output=True, text=True, shell=True)`.
  - security test case:
    1. Start Flask sample app (`make run` in `/code/sample-apps/flask-mysql/`).
    2. Access `http://localhost:8086/shell`.
    3. Enter malicious command (e.g., `ls -la ; cat /etc/passwd`) in the "Command" form.
    4. Submit form, observe command execution on the page.
    5. Repeat on non-firewall port (8087) to confirm bypass.

- vulnerability name: SQL Injection in Django and Flask Sample Apps
  - description: Multiple Django and Flask sample apps use string formatting for SQL queries in `/create` endpoints, making them vulnerable to SQL injection. Attackers can inject malicious SQL via the `dog_name` parameter.
  - impact: High. Unauthorized data access, modification, deletion, database compromise.
  - vulnerability rank: high
  - currently implemented mitigations: Aikido Zen `protect()` is ineffective for custom SQL queries.
  - missing mitigations: Parameterized queries, ORM usage, Zen firewall enhancement or configuration guidance.
  - preconditions: Django/Flask sample app running and `/create` endpoint accessible.
  - source code analysis: Vulnerable code in `create_dogpage` or `create_dog` views of sample apps, using string formatting for SQL queries. Example: `/code/sample-apps/django-mysql/sample_app/views.py`.
  - security test case:
    1. Start vulnerable sample app (`make run` in `/code/sample-apps/django-mysql/`).
    2. Access `http://localhost:8080/app/create`.
    3. Enter SQL injection payload (e.g., `Malicious dog", "Injected wrong boss name"); -- `) in "Dog name" form.
    4. Submit form, verify injection by checking "boss_name" on homepage (`http://localhost:8080/app`).
    5. Repeat on non-firewall port (8081) to confirm bypass.

- vulnerability name: NoSQL Injection in Flask Mongo Sample App
  - description: Flask Mongo sample app `/code/sample-apps/flask-mongo/app.py` `/auth` endpoint is vulnerable to NoSQL injection. Unsanitized user input in JSON body is used to construct MongoDB queries, allowing NoSQL operator injection.
  - impact: Medium. Unauthorized data access, potential database operation manipulation.
  - vulnerability rank: medium
  - currently implemented mitigations: Aikido Zen `protect()` is ineffective for NoSQL injection in Flask-PyMongo custom queries.
  - missing mitigations: Input validation, secure authentication, Zen firewall NoSQL injection detection enhancement.
  - preconditions: Flask Mongo sample app running and `/auth` endpoint accessible.
  - source code analysis: Vulnerable code in `/code/sample-apps/flask-mongo/app.py` at `/auth` endpoint, directly using JSON request data in `mongo.db.dogs.find_one(dog_info)`.
  - security test case:
    1. Start Flask Mongo sample app (`make run` in `/code/sample-apps/flask-mongo/`).
    2. Send POST request to `http://localhost:8094/auth` with JSON payload: `{"dog_name": "Doggo 1", "pswd": { "$ne": ""}}`.
    3. Verify successful authentication despite incorrect password, confirming NoSQL injection.
    4. Repeat on non-firewall port (8095) to confirm bypass.