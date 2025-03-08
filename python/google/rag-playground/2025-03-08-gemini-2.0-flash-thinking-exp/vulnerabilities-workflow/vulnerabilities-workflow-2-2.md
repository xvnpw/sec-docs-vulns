- Vulnerability Name: Reflected Cross-Site Scripting (XSS)
- Description:
    1. An attacker can input malicious JavaScript code into the "Retrieval Queries" text area in the "Configure Experiments" page of the Streamlit frontend.
    2. When the user submits the query, the frontend sends this malicious payload to the backend API endpoint `/retrieval/compare-retrieval-results` as part of the request body.
    3. The backend processes the query and generates an answer using the RAG pipeline.
    4. The backend's answer generation service at `/answer_generation_service` returns a JSON response that includes the user-provided query and the generated answer.
    5. The frontend receives this JSON response and, in the `display_results` function within `2_🧪_Configure_Experiments.py`, renders the `answer` field using `st.markdown`.
    6. `st.markdown` interprets the answer as Markdown and renders it as HTML. If the answer contains malicious JavaScript (which can be injected via the initial query), this script will be executed in the user's web browser when the page is rendered, leading to XSS.

- Impact:
    Successful exploitation of this vulnerability can have severe consequences:
    - Account Takeover: An attacker could potentially steal session cookies or other sensitive information, leading to account hijacking.
    - Data Theft: Malicious scripts can access data within the browser's context, potentially exfiltrating sensitive information.
    - Malware Distribution: The vulnerability could be used to redirect users to malicious websites or initiate downloads of malware.
    - Defacement: An attacker could alter the appearance of the web page presented to the user.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
    No explicit input sanitization or output encoding/escaping is implemented in the provided code to prevent XSS. The frontend directly renders the backend's response using `st.markdown` without any security measures.

- Missing Mitigations:
    - Input Sanitization: Implement robust input sanitization on the backend to remove or neutralize any potentially malicious HTML or JavaScript code within the user queries before processing and storing or returning them.
    - Output Encoding/Escaping: On the frontend, before displaying any user-generated content or data received from the backend (especially the `answer` field), implement proper output encoding or escaping. For Streamlit, consider using `st.text` or escaping HTML entities before passing data to `st.markdown` if HTML rendering is necessary for other parts of the content but not for user-provided parts.  Alternatively, if HTML rendering is not needed for the answers, use `st.text` to display the answers as plain text, which inherently prevents XSS.

- Preconditions:
    - The attacker must have network access to the RAG Playground application.
    - The application must be running and accessible, specifically the Streamlit frontend and backend API.
    - A user must interact with the "Configure Experiments" page and execute a query containing the malicious payload.

- Source Code Analysis:
    1. Frontend Input (`/code/frontend/pages/2_🧪_Configure_Experiments.py`):
       - User input is collected in the `st.text_area("Retrieval Queries ...")` component.
       - The input queries are stored in the `rag_queries` variable.
    2. Frontend Request to Backend (`/code/frontend/pages/2_🧪_Configure_Experiments.py`):
       - When the form is submitted, a POST request is made to the backend endpoint `/retrieval/compare-retrieval-results`.
       - The `queries` list, derived from `rag_queries`, is included in the JSON payload sent to the backend.
    3. Backend Processing and Response (`/code/backend/answer_generation_service/main.py`):
       - The `execute_rag_query` function in the backend receives the query.
       - The function generates an answer and constructs a JSON response.
       - The JSON response includes the original `query` and the generated `answer` in its body.
    4. Frontend Rendering of Results (`/code/frontend/pages/2_🧪_Configure_Experiments.py`):
       - The `display_results` function is called to present the experiment results.
       - For each result, the `answer` is extracted using `result.get('answer', 'N/A')`.
       - The answer is then rendered using `st.markdown(f"{result.get('answer', 'N/A')}")`.
       - **Vulnerable Code Snippet:**
         ```python
         st.markdown("**Answer:**")
         st.markdown(f"{result.get('answer', 'N/A')}")
         ```
       - `st.markdown` interprets and renders the string as Markdown, including HTML and JavaScript.

- Security Test Case:
    1. Access the deployed RAG Playground application in a web browser.
    2. Navigate to the "🧪 Configure Experiments" page using the sidebar or navigation buttons.
    3. Locate the "Retrieval Queries" text area on the page.
    4. Input the following XSS payload into the "Retrieval Queries" text area:
       ```html
       <img src=x onerror="alert('XSS Vulnerability')" />
       ```
    5. Select any options for "Select retrieval techniques" and "Select LLMs". These choices are not critical for triggering the XSS.
    6. Click the "🚀 Run Experiment" button to submit the query.
    7. After a short processing time, the "Experiment Results" section will appear.
    8. **Expected Outcome (Vulnerability Confirmation):** An alert box should pop up in the browser window displaying the message "XSS Vulnerability". This confirms that the JavaScript code injected in the query was executed, demonstrating a successful XSS attack.
    9. If the alert box appears, the Reflected Cross-Site Scripting vulnerability is validated. If no alert box appears, re-examine the steps and ensure the application is functioning as expected and the payload was correctly injected.