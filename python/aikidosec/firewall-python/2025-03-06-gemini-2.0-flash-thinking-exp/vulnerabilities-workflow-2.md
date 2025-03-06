# Vulnerabilities

## SQL Injection in Django and Flask Sample Apps

This vulnerability exists due to the use of direct string formatting in SQL queries within the `create_dogpage` view in the Django sample app and the `create_dog` route in the Flask sample app. An attacker can inject malicious SQL code through the `dog_name` input, leading to unauthorized database access and manipulation.

### Description
1. The Django and Flask sample applications use direct string formatting in SQL queries within the `create_dogpage` view (Django) and `create_dog` route (Flask).
2. An attacker can craft a malicious `dog_name` input containing SQL injection payloads.
3. When the application processes this input, the injected SQL code is executed directly against the database.
4. This can lead to unauthorized data access, modification, or deletion.

### Impact
- High. Successful exploitation can lead to full database compromise, including data exfiltration, modification, and deletion. This can severely impact data confidentiality, integrity, and availability.

### Vulnerability Rank
High

### Currently Implemented Mitigations
- The project aims to mitigate this vulnerability using the Zen in-app firewall. When properly installed and configured, Zen should detect and block SQL injection attempts, as described in the project documentation and README.md.

### Missing Mitigations
- The sample applications themselves lack any input validation, sanitization, or use of parameterized queries. They are intentionally designed to be vulnerable to demonstrate the firewall's capabilities. In a real-world application, proper input handling and secure coding practices should be implemented in addition to using a WAF.

### Preconditions
- The Django or Flask sample application must be running and accessible.
- Zen firewall might be disabled or misconfigured to allow the vulnerability to be exposed.

### Source Code Analysis
- **Django Sample App (/code/sample-apps/django-mysql/sample_app/views.py):**
    ```python
    def create_dogpage(request):
        ...
        elif request.method == 'POST':
            dog_name = request.POST.get('dog_name')
            # Using custom sql to create a dog :
            with connection.cursor() as cursor:
                query = 'INSERT INTO sample_app_dogs (dog_name, dog_boss) VALUES ("%s", "N/A")' % dog_name
                print("QUERY : ", query)
                cursor.execute(query)
            return HttpResponse("Dog page created")
    ```
    The `dog_name` from user input is directly inserted into the SQL query string without any sanitization or parameterization, leading to SQL injection.
- **Flask Sample App (/code/sample-apps/flask-mysql/app.py):**
    ```python
    @app.route("/create", methods=['POST'])
    def create_dog():
        dog_name = request.form['dog_name']
        connection = mysql.get_db()
        cursor = connection.cursor()
        cursor.execute(f'INSERT INTO dogs (dog_name, isAdmin) VALUES ("%s", 0)' % (dog_name))
        connection.commit()
        return f'Dog {dog_name} created successfully'
    ```
    Similar to the Django app, the Flask app directly embeds the `dog_name` into the SQL query string using f-string formatting, making it vulnerable to SQL injection.

### Security Test Case
1. Deploy the `django-mysql` or `flask-mysql` sample application with Zen firewall disabled (using `make runZenDisabled`).
2. Access the create dog page: `http://localhost:8080/app/create` (Django) or `http://localhost:8086/create` (Flask).
3. Submit a form with `dog_name` set to a malicious SQL payload: `Malicious dog', TRUE); -- `.
4. Observe that the application processes the request without blocking.
5. Verify the SQL injection by checking the database for unexpected changes or by observing error messages if the injection causes an error. For example in Django sample app, you can check the dog page and see that boss name is not "N/A".
6. Deploy the same application with Zen firewall enabled (`make run`).
7. Repeat step 3 and observe that the application returns a 500 error, indicating that Zen has blocked the request and prevented the SQL injection. Check the mock Aikido Core server logs to confirm the attack detection event.

## Command Injection in Flask MySQL Sample App

This vulnerability is present in the Flask MySQL sample application due to the `/shell` route, which executes system commands using `subprocess.run` with `shell=True`. An attacker can inject arbitrary shell commands through the `command` form field or URL parameter, leading to potential server compromise.

### Description
1. The Flask MySQL sample application includes a `/shell` route that executes system commands using `subprocess.run` with `shell=True`.
2. An attacker can inject arbitrary shell commands by providing malicious input to the `command` form field or `command` URL parameter.
3. The application directly executes the provided command, without sanitization, on the server's operating system.
4. This can lead to complete server compromise, allowing the attacker to read sensitive files, modify system configurations, or launch further attacks.

### Impact
- Critical. Successful exploitation allows for arbitrary command execution on the server, potentially leading to full system compromise, data breach, and denial of service.

### Vulnerability Rank
Critical

### Currently Implemented Mitigations
- The project aims to mitigate this vulnerability using the Zen in-app firewall. When properly installed and configured, Zen should detect and block command injection attempts.

### Missing Mitigations
- The sample application lacks any input validation or sanitization for the command input. It directly passes user input to `subprocess.run` without any security measures. Real-world applications should avoid executing user-provided commands directly and, if necessary, should use secure methods like parameterized commands or strictly validated input.

### Preconditions
- The Flask MySQL sample application must be running and accessible.
- The `/shell` route must be exposed.
- Zen firewall might be disabled or misconfigured to allow the vulnerability to be exposed.

### Source Code Analysis
- **Flask MySQL App (/code/sample-apps/flask-mysql/app.py):**
    ```python
    @app.route("/shell", methods=['POST'])
    def execute_command():
        command = request.form['command']
        result = subprocess.run(command, capture_output=True, text=True, shell=True)
        return str(result.stdout)

    @app.route("/shell/<string:command>", methods=['GET'])
    def execute_command_get(command):
        result = subprocess.run(command, capture_output=True, text=True, shell=True)
        return str(result.stdout)
    ```
    The `command` obtained from the form or URL parameter is directly passed to `subprocess.run` with `shell=True`, enabling command injection.

### Security Test Case
1. Deploy the `flask-mysql` sample application with Zen firewall disabled (using `make runZenDisabled`).
2. Access the shell execution form: `http://localhost:8086/shell`.
3. In the `command` field, enter a malicious shell command: `ls -la`.
4. Observe that the application executes the command and displays the output, confirming command injection vulnerability. Alternatively, use GET request `http://localhost:8086/shell/ls -la`
5. Deploy the same application with Zen firewall enabled (`make run`).
6. Repeat step 3 and observe that the application returns a 500 error, indicating that Zen has blocked the request. Check the mock Aikido Core server logs to confirm the attack detection event.