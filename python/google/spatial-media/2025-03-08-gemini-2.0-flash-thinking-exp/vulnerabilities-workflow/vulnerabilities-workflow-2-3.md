### Vulnerability List:

- Vulnerability Name: XML External Entity (XXE) Injection in Spherical Metadata Parsing
- Description:
    1. An attacker crafts a malicious media file (e.g., MP4 or MOV) containing spherical video metadata.
    2. Within the XML metadata, the attacker injects an XML External Entity (XXE) payload. This payload can reference external entities, such as local files on the system where the `spatial media tools` are run.
    3. The user, unaware of the malicious nature of the file, uses the `spatial media tools` (specifically `spatialmedia` command-line tool or GUI) to examine or inject metadata into this file.
    4. When the tool parses the malicious XML metadata using `xml.etree.ElementTree.XML`, it processes the external entity references.
    5. Due to the lack of proper XXE protection in the XML parser configuration, the tool attempts to resolve and process the external entity, which can lead to:
        - **Local file disclosure:** If the XXE payload is crafted to read a local file (e.g., `/etc/passwd`), the content of this file may be disclosed to the attacker if the tool outputs the parsed metadata to the console or logs.
- Impact:
    - **High**: An attacker can potentially read arbitrary local files from the system where the `spatial media tools` are executed. This can lead to the disclosure of sensitive information, such as configuration files, application data, or even system files, depending on the permissions of the user running the tool.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - None identified in the provided source code. The code uses `xml.etree.ElementTree.XML` for parsing XML metadata without any apparent measures to disable or sanitize external entity processing.
- Missing Mitigations:
    - **Disable external entity resolution:** When parsing XML, the `xml.etree.ElementTree` parser should be configured to disable external entity resolution. This can be achieved by using `XMLParser` with `resolve_entities=False` and `forbid_doctype=True` if using Python 3.7 or later. For older versions, more manual sanitization or using a safer XML parsing library might be needed.
    - **Input validation and sanitization:** While disabling XXE is the primary mitigation, further input validation and sanitization of the XML metadata could provide defense in depth. However, for XXE, disabling external entity resolution is the most effective and recommended approach.
- Preconditions:
    - The attacker needs to create a maliciously crafted media file (MP4 or MOV) with an embedded XXE payload in the spherical video metadata section.
    - The user must use the `spatial media tools` to process this malicious file, either by examining it using the command-line tool or opening it in the GUI application.
- Source Code Analysis:
    - File: `/code/spatialmedia/metadata_utils.py`
    - Function: `parse_spherical_xml(contents, console)`
    - Vulnerable Code Snippet:
      ```python
      parsed_xml = xml.etree.ElementTree.XML(contents)
      ```
    - Step-by-step analysis:
        1. The `parse_spherical_xml` function is responsible for parsing the XML metadata extracted from media files.
        2. It uses `xml.etree.ElementTree.XML(contents)` to parse the XML string `contents`.
        3. The `xml.etree.ElementTree.XML` function, by default, in Python versions (especially older ones like Python 2.7, as suggested for this tool) is susceptible to XXE injection if the XML payload contains external entity declarations and references.
        4. The code does not include any explicit steps to disable external entity resolution or to use a secure XML parser configuration.
        5. Consequently, if the `contents` variable contains a malicious XML payload with XXE, the parser will attempt to resolve external entities, potentially leading to file disclosure or other XXE-related vulnerabilities.
- Security Test Case:
    1. **Prepare Malicious MP4 File:**
        - Create a dummy MP4 file (you can use any MP4 file and then modify its metadata). Let's name it `malicious.mp4`.
        - Using a hex editor or a metadata editing tool, locate the spherical video metadata section within the MP4 file. This section is typically within a `uuid` box with UUID `ffcc8263-f855-4a93-8814-587a02521fdd`.
        - Replace the existing spherical metadata XML with the following malicious XML payload:
          ```xml
          <?xml version="1.0"?>
          <!DOCTYPE rdf:RDF [
            <!ENTITY xxe SYSTEM "file:///etc/passwd">
          ]>
          <rdf:SphericalVideo
            xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"
            xmlns:GSpherical="http://ns.google.com/videos/1.0/spherical/">
            <GSpherical:Spherical>true</GSpherical:Spherical>
            <GSpherical:Stitched>true</GSpherical:Stitched>
            <GSpherical:StitchingSoftware>XXE Test</GSpherical:StitchingSoftware>
            <GSpherical:ProjectionType>equirectangular</GSpherical:ProjectionType>
            <GSpherical:XXE>&xxe;</GSpherical:XXE>
          </rdf:SphericalVideo>
          ```
          **Note:** If directly editing binary is complex, you can also try to inject metadata with a benign XML first, then replace the XML content within the file with the malicious one.
    2. **Run `spatialmedia` tool to examine the malicious file:**
        - Open a terminal and navigate to the directory containing `spatialmedia` tool (where `spatialmedia` or `spatialmedia.py` script is located).
        - Execute the command: `python spatialmedia malicious.mp4`
    3. **Observe the output:**
        - Examine the console output. If the XXE vulnerability is present, you might see the content of `/etc/passwd` printed in the console, possibly within the output related to the `GSpherical:XXE` tag, or an error message indicating an attempt to access or process the external entity.
        - If the tool attempts to read and display `/etc/passwd`, it confirms the XXE vulnerability.