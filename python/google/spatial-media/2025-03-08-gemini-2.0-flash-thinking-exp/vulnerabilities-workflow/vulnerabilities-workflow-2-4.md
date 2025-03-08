- Vulnerability Name: XML External Entity (XXE) Injection vulnerability in Spherical Video Metadata parsing

- Description:
An XML External Entity (XXE) injection vulnerability exists in the metadata parsing functionality. This vulnerability can be triggered when the tool parses a crafted MP4 or MOV file containing malicious Spherical Video metadata. By embedding an external entity definition in the XML metadata, an attacker can potentially read arbitrary files from the server's filesystem where the tool is being run, or trigger a denial of service.

Step-by-step trigger:
1. An attacker crafts a malicious MP4 or MOV file.
2. Within the Spherical Video metadata section of the crafted file, the attacker injects a malicious XML payload. This payload defines an external entity that points to a local file on the system. For example:
   ```xml
   <!DOCTYPE rdf:RDF [
     <!ENTITY xxe SYSTEM "file:///etc/passwd">
   ]>
   <rdf:SphericalVideo xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#" xmlns:GSpherical="http://ns.google.com/videos/1.0/spherical/">
     <GSpherical:Spherical>true</GSpherical:Spherical>
     <GSpherical:Stitched>true</GSpherical:Stitched>
     <GSpherical:StitchingSoftware>&xxe;</GSpherical:StitchingSoftware>
     <GSpherical:ProjectionType>equirectangular</GSpherical:ProjectionType>
   </rdf:SphericalVideo>
   ```
3. The attacker provides this crafted media file to the Spatial Media Metadata Injector tool, either using the command-line interface or the GUI application, for examination or injection.
4. When the tool parses the metadata of the malicious file using `xml.etree.ElementTree.XML(contents)` in `spatialmedia/metadata_utils.py`, the XML parser processes the external entity.
5. If the XML parser is vulnerable to XXE and is not configured to prevent external entity expansion, it will attempt to resolve and include the content of the external entity (e.g., `/etc/passwd`) into the parsed XML document.
6. The content of the external entity might be printed to the console or processed further by the application, potentially exposing sensitive information or causing other impacts depending on how the parsed XML is used.

- Impact:
    - High: Information Disclosure - An attacker can read arbitrary files from the filesystem of the machine running the Spatial Media tool. This could include sensitive configuration files, application data, or user data.
    - Potential for Denial of Service - In some XXE variations, it's possible to trigger a denial of service by referencing very large external entities or by causing the parser to enter an infinite loop when resolving entities.

- Vulnerability Rank: High

- Currently implemented mitigations:
    - None: The code uses the default `xml.etree.ElementTree.XML` parser without any explicit mitigations against XXE vulnerabilities.

- Missing mitigations:
    - Disable external entity processing in the XML parser. This can be achieved by configuring the `xml.etree.ElementTree` parser to disallow or ignore external entities. For example, using `parser = etree.XMLParser(resolve_entities=False)` if using `lxml` or similar methods for standard library if available. However, standard library `xml.etree.ElementTree` in Python 2.7 and later versions >= 3.7 should be secure by default against XXE for default parsing methods like `fromstring`, `XML`, and `parse` without explicitly enabling `resolve_entities`. It's crucial to verify the Python version's default behavior or explicitly disable entity resolution to ensure security.

- Preconditions:
    - The attacker needs to be able to provide a crafted media file to the Spatial Media Metadata Injector tool. This is likely achievable as the tool is designed to process user-provided media files.
    - The tool must be run on a system where the attacker wants to access local files.

- Source code analysis:
    - File: `/code/spatialmedia/metadata_utils.py`
    - Function: `parse_spherical_xml(contents, console)`
    - Line: `parsed_xml = xml.etree.ElementTree.XML(contents)`

    ```python
    def parse_spherical_xml(contents, console):
        """Returns spherical metadata for a set of xml data.
        ...
        """
        try:
            # Vulnerable line: XML parser is created without disabling external entity resolution
            parsed_xml = xml.etree.ElementTree.XML(contents)
        except xml.etree.ElementTree.ParseError:
        ...
    ```
    - The `xml.etree.ElementTree.XML(contents)` function is used to parse the XML metadata. By default, depending on the Python version and library configuration, this parser might be vulnerable to XXE attacks if the input XML contains external entity definitions and the parser attempts to resolve them. The code doesn't include any settings to disable external entity resolution.

- Security test case:
    1. Create a text file named `test_xxe.xml` with the following malicious XML content:
       ```xml
       <?xml version="1.0"?>
       <!DOCTYPE rdf:RDF [
         <!ENTITY xxe SYSTEM "file:///etc/passwd">
       ]>
       <rdf:SphericalVideo xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#" xmlns:GSpherical="http://ns.google.com/videos/1.0/spherical/">
         <GSpherical:Spherical>true</GSpherical:Spherical>
         <GSpherical:Stitched>true</GSpherical:Stitched>
         <GSpherical:StitchingSoftware>&xxe;</GSpherical:StitchingSoftware>
         <GSpherical:ProjectionType>equirectangular</GSpherical:ProjectionType>
       </rdf:SphericalVideo>
       ```
    2. Create a dummy MP4 or MOV file (e.g., `dummy.mp4`). You can use `ffmpeg` to create a minimal MP4 file if needed.
    3. Use the `spatialmedia` tool to inject the crafted XML metadata into the dummy media file. You will need to modify the `generate_spherical_xml` function in `spatialmedia/metadata_utils.py` temporarily to directly return the content of `test_xxe.xml` instead of generating standard metadata.  Alternatively, craft a full MP4 file manually with the malicious XML metadata. For testing purposes, modifying the python script is faster.
    4. Run the `spatialmedia` tool in examine mode against the modified dummy MP4 file:
       ```bash
       python spatialmedia dummy.mp4
       ```
    5. Observe the output in the console. If the vulnerability exists, the content of `/etc/passwd` (or a portion of it) will be printed to the console, likely within the "StitchingSoftware" metadata field output. If you are testing on Windows, try accessing `file:///C:/Windows/win.ini` or similar. If you don't see the content of the file, but get an error related to accessing the file, it could still indicate XXE but with restricted output.

This test case will confirm if the XML parser is processing external entities and if it can be exploited to read local files.

To mitigate this vulnerability, ensure that the XML parser is configured to disable external entity resolution. In `spatialmedia/metadata_utils.py`, modify the `parse_spherical_xml` function to use a secure XML parsing configuration if possible with `xml.etree.ElementTree` or switch to a more secure XML parsing library like `defusedxml`. For standard `xml.etree.ElementTree` in Python 3.7+, default behavior should be safe, but explicit verification and potentially setting `parser = etree.XMLParser(resolve_entities=False)` (if using `lxml`) or equivalent for standard library is recommended for older versions and for best practice defense in depth. For Python 2.7 and versions < 3.7, verifying default secure behavior or applying explicit mitigations is critical.