## Vulnerability Report

### XML External Entity Injection (XXE) in Spherical Video Metadata Parsing

*   **Description:**
    1.  An attacker crafts a malicious MP4 or MOV file containing spherical video metadata.
    2.  This malicious metadata includes an XML External Entity (XXE) payload within the `<rdf:SphericalVideo>` tag. This payload can define external entities, pointing to local files or external URLs.
    3.  When the `spatialmedia` tool or a media player using this library parses the metadata of this file, the XML parser processes the embedded XML. This can occur when using the `spatialmedia` command-line tool to examine metadata, inject metadata, or if the library is used within a media player application.
    4.  The code uses `xml.etree.ElementTree.XML` to parse the XML data. Standard `ElementTree` in Python (prior to versions addressing XXE vulnerabilities) is vulnerable to XXE if not configured to disable external entity processing.
    5.  If the XML parser is not configured to disable external entity processing, it will attempt to resolve the external entity.
    6.  This can lead to the disclosure of local files on the server or client system processing the file, or Server-Side Request Forgery (SSRF) if the external entity points to an external URL. For example, an attacker can read sensitive files like `/etc/passwd` or `C:/Windows/win.ini`.

*   **Impact:**
    -   High: Information Disclosure - An attacker can potentially read arbitrary files from the system's filesystem where the `spatial media tool` or vulnerable media player is running. This can lead to the disclosure of sensitive information, such as configuration files, application data, or user data.
    -   Server-Side Request Forgery (SSRF) - In certain scenarios, it could lead to Server-Side Request Forgery (SSRF) if the external entity points to an external URL, potentially allowing further attacks on internal systems or external resources.

*   **Vulnerability Rank:** High

*   **Currently Implemented Mitigations:**
    -   None: The code uses `xml.etree.ElementTree.XML` to parse XML data in `spatialmedia/metadata_utils.py`. Review of the code and library usage does not show any explicit mitigations against XXE vulnerabilities when parsing spherical video metadata. The default `xml.etree.ElementTree.XML` parser is used without any configuration to disable external entity resolution.

*   **Missing Mitigations:**
    -   Disable external entity processing in the XML parser. When parsing XML metadata, the `xml.etree.ElementTree.XMLParser` should be configured to disallow external entity loading. This can be achieved by using `XMLParser(resolve_entities=False)` if using a parser factory or ensuring safe parsing practices are applied if directly using `ElementTree.XML`. For example, using `parser = XMLParser(resolve_entities=False)` or setting `parser.parser.feed_entity_defs = False` if using a custom parser.

*   **Preconditions:**
    -   The victim must process a maliciously crafted MP4 or MOV file using the `spatialmedia` tool (e.g., using the `spatialmedia` command-line tool to examine metadata or if the library is used within a media player application). This includes using the tool via command-line or GUI to examine or inject metadata.
    -   The attacker needs to be able to provide or trick the victim into processing the malicious spatial media file. This is likely achievable as the tool is designed to process user-provided media files.

*   **Source Code Analysis:**
    1.  **File:** `/code/spatialmedia/metadata_utils.py`
    2.  **Function:** `parse_spherical_xml(contents, console)`
    3.  **Code Snippet:**
        ```python
        try:
            parsed_xml = xml.etree.ElementTree.XML(contents)
        except xml.etree.ElementTree.ParseError:
            # ... error handling ...
            try:
                # ... more parsing attempts ...
                parsed_xml = xml.etree.ElementTree.XML(contents)
                # ... warning message ...
            except xml.etree.ElementTree.ParseError as e:
                # ... error handling ...
                return
        ```
    4.  **Analysis:** The code uses `xml.etree.ElementTree.XML(contents)` to parse the XML metadata string.  By default, `xml.etree.ElementTree` in older Python versions or without explicit security configurations, is vulnerable to XXE attacks. The code does not show any explicit steps to disable external entity resolution during XML parsing. An attacker can embed a malicious XML payload within the spherical metadata of a video file. When this file is processed by the `spatialmedia` tool or any application using this library to parse metadata, and if the XML parser attempts to resolve external entities, it could lead to XXE. The parsed XML is then processed to extract metadata tags. If the XML contains an external entity definition, and the parser attempts to resolve it, the XXE vulnerability is triggered.

*   **Security Test Case:**
    1.  **Craft a malicious MP4 file:** Create a dummy MP4 file (e.g., `dummy.mp4`). This can be an empty MP4 container or a simple valid MP4 file.
    2.  **Create a malicious XML payload:** Create an XML file (e.g., `xxe_payload.xml`) with an XXE payload. For example, to attempt to read the `/etc/passwd` file on a Linux system:
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
          <GSpherical:StitchingSoftware>XXE Attack</GSpherical:StitchingSoftware>
          <GSpherical:ProjectionType>equirectangular</GSpherical:ProjectionType>
          <GSpherical:Description>&xxe;</GSpherical:Description>
        </rdf:SphericalVideo>
        ```
    3.  **Inject the malicious XML metadata into the MP4 file:** Use a Python script or a metadata injection tool to inject the malicious XML payload as spherical metadata into the dummy MP4 file, replacing any existing metadata or creating it if none exists.
    4.  **Run the spatialmedia tool to examine the metadata:** Execute the command `python spatialmedia <malicious_video.mp4>` (replace `<malicious_video.mp4>` with the name of your crafted file).
    5.  **Observe the output:** If the vulnerability exists, the output might contain the contents of `/etc/passwd` printed in the console, or error messages indicating an attempt to access or process the external entity. Examine the console output for any unusual output, errors related to file access, or the content of the targeted file (e.g., `/etc/passwd`). To test for external interaction, you can modify the XXE payload to point to an external URL (e.g., `http://example.com/test_xxe`) and monitor network traffic using tools like `tcpdump` or `Wireshark` to see if a request is made to the external URL when `spatialmedia` parses the file.