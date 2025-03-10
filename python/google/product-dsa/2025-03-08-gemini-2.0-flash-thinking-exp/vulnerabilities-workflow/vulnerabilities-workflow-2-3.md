### Vulnerability List

* Vulnerability Name: Malicious URL Injection in Dynamically Generated Ads

* Description:
An attacker can inject malicious URLs into product titles or descriptions within the Google Merchant Center (GMC) feed. When Product DSAs processes this feed to generate Dynamic Search Ads (DSAs), these malicious URLs are incorporated into the ads without proper sanitization. As a result, when users click on these dynamically generated ads, they are redirected to attacker-controlled websites instead of the intended product pages.

* Impact:
Users clicking on ads generated by Product DSAs can be redirected to malicious websites. This can lead to various negative consequences, including:
    - **Phishing attacks:** Users might be tricked into entering credentials or sensitive information on fake websites mimicking legitimate ones.
    - **Malware distribution:** Users' devices could be infected with malware by visiting attacker-controlled websites.
    - **Reputation damage:** The organization running Product DSAs and its Google Ads campaigns can suffer reputational damage due to users being redirected to malicious content through their ads.
    - **Financial loss:** Misleading ads can lead to ineffective ad spending and lost potential sales.

* Vulnerability Rank: High

* Currently Implemented Mitigations:
None. The code does not include any input sanitization or validation for product titles or descriptions before using them in ad generation.

* Missing Mitigations:
    - **Input Sanitization:** Implement robust sanitization of product titles and descriptions fetched from the GMC feed. This should include:
        - URL validation: Check if URLs are well-formed and potentially block or sanitize suspicious URLs.
        - HTML encoding: Encode HTML special characters to prevent interpretation as HTML code.
        - JavaScript removal: Strip out any JavaScript or other potentially malicious code from text fields.
    - **Content Security Policy (CSP):** Implement CSP headers to further mitigate the risk of XSS if any malicious code bypasses sanitization. Although, in this case, the primary risk is open redirect, CSP can be a general security improvement.

* Preconditions:
    - The attacker needs to have the ability to modify product data within the Google Merchant Center feed associated with the Google Ads account used by Product DSAs. This could be achieved if the attacker has compromised the GMC account or if there are vulnerabilities in the GMC data management processes.
    - Product DSAs application must be installed and configured to use the compromised GMC feed.
    - The dynamic search ad campaigns generated by Product DSAs must be running in Google Ads.

* Source Code Analysis:

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

* Security Test Case:

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