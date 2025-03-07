- Vulnerability Name: Unvalidated Log Folder Path Leading to Potential Local File System Access

- Description:
    1. An attacker can modify the 'Logs Folder' path in the plugin settings to an arbitrary location on the local file system.
    2. When the plugin logs events or errors, it will write log files to the attacker-specified directory.
    3. If the attacker sets the 'Logs Folder' to a sensitive directory they control or a directory accessible to other users, they might gain unintended access or leak information through the log files created by the plugin.
    4. Although this is not a direct path traversal to read arbitrary files, it allows an attacker to write files to arbitrary locations, which in some scenarios could be leveraged for further attacks or information disclosure depending on the system configuration and permissions.

- Impact:
    - Low to Medium.
    - An attacker can write log files to arbitrary locations on the user's file system.
    - Depending on system configuration and permissions, this could potentially lead to:
        - Information disclosure if log files contain sensitive data and are written to a publicly accessible directory.
        - Local privilege escalation if log files are written to a system directory and can be manipulated.
        - In most common scenarios, the impact is limited to writing files in user-writable directories.

- Vulnerability Rank: Medium

- Currently Implemented Mitigations:
    - None. The application allows users to specify any folder path without validation.

- Missing Mitigations:
    - Input validation and sanitization for the 'Logs Folder' path to ensure it stays within the intended plugin directory or a predefined safe location.
    - Restricting user input to only allow selection within a specific directory or using a predefined path.
    - Displaying a warning message to the user when they choose a log folder outside of the default plugin directory.

- Preconditions:
    - The attacker needs to have access to the QGIS application settings where the Azure Maps Creator plugin settings can be modified. This typically requires local access to the user's machine or the ability to manipulate QGIS settings through other means (unlikely in typical external attack scenarios for QGIS plugins).

- Source Code Analysis:
    1. **File: `/code/src/azure_maps_plugin_dialog.py`**
        ```python
        class AzureMapsPluginDialog(QtWidgets.QDialog, FORM_CLASS):
            # ...
            def __init__(self, iface, parent=None):
                # ...
                plugin_dir = QgsApplication.qgisSettingsDirPath().replace("\\", "/")
                config_path = plugin_dir + Constants.Paths.RELATIVE_CONFIG_PATH
                self.plugin_settings = QSettings(config_path, QSettings.IniFormat)

                # Logs
                default_logs_folder = plugin_dir + Constants.Paths.RELATIVE_PLUGIN_PATH + "/{}".format(Constants.Logs.LOG_FOLDER_NAME)
                self.logsFolderPicker.setDefaultRoot(self.plugin_settings.value("logsFolder", default_logs_folder))
                self.logsFolderPicker.setFilePath(self.plugin_settings.value("logsFolder", default_logs_folder))

            def saveSettings(self):
                # Creator
                # ...
                self.plugin_settings.setValue("logsFolder", self.logsFolderPicker.filePath())
        ```
        - The `AzureMapsPluginDialog` class initializes `logsFolderPicker` with a default path within the QGIS plugin directory.
        - `self.logsFolderPicker.setFilePath()` and `self.logsFolderPicker.setDefaultRoot()` are used to set the initial directory displayed in the folder picker dialog, and the initially selected file path.
        - The `saveSettings` function saves the user-selected path from `self.logsFolderPicker.filePath()` into the plugin settings without any validation.

    2. **File: `/code/src/azure_maps_plugin.py`**
        ```python
        class AzureMapsPlugin:
            # ...
            def _create_helpers(self):
                """Create helpers for the plugin. Setup Logger and AzureMapsRequestHandler"""
                self.logger = AzureMapsPluginLogger(self.iface,
                                    hideSubscriptionKey=True,
                                    subscription_key=self.dlg.subKey.text(),
                                    autoLogToFile=True,
                                    logFolder=self.dlg.logsFolderPicker.filePath(),
                                    debugLog=False)
                # ...
        ```
        - In `_create_helpers`, the `AzureMapsPluginLogger` is instantiated, and the `logFolder` parameter is directly passed from `self.dlg.logsFolderPicker.filePath()`, which is user-controlled input from the dialog settings.

    3. **File: `/code/src/helpers/AzureMapsPluginLogger.py`**
        ```python
        class AzureMapsPluginLogger:
            # ...
            def __init__(self, iface, hideSubscriptionKey=True, subscription_key=None,
                            dataset_id=None,
                            autoLogToFile=True, logFolder=None, debugLog=False):
                # ...
                self.logFolder = logFolder # Folder to save log files
                # ...
                self.setupLogFile()

            def setLogFolder(self, logFolder):
                """
                Set log folder path and create folder if it doesn't exist
                Set log file path variable
                Set error log folder path and create folder if it doesn't exist
                """
                self.errorLogFolderStatus = True # Set error log folder status to True, so error log folder message can be printed
                self.logFolder = logFolder
                if self.logFolder and self._check_folder_path():
                    if not os.path.exists(self.logFolder):
                        os.mkdir(self.logFolder)
                    self.logFilePath = "{}/{}".format(self.logFolder, self.logFileName)
                    self.errorLogFolderPath = "{}/{}".format(self.logFolder, self.errorLogFolderName)
                    if not os.path.exists(self.errorLogFolderPath):
                        os.mkdir(self.errorLogFolderPath)
            # ...
            def writeLog(self, level, log_text, logFile=None):
                """Write log to file"""
                # ...
                if not logFile: logFile = self.logFilePath
                if logFile:
                    with open(logFile, "a") as f: # Vulnerable file write operation
                        f.write("{}{sb_str}{}\n".format(self._generateLogDateTime(), log_text, sb_str=sb_str))
        ```
        - The `AzureMapsPluginLogger` class takes the `logFolder` path in its constructor and `setLogFolder` method.
        - The `writeLog` method uses `open(logFile, "a") as f:` to write log entries to the file path specified by `self.logFilePath`, which is directly derived from the user-provided `logFolder` without any path validation or sanitization. This allows writing to any location the user has write permissions to.

- Security Test Case:
    1. Open QGIS Desktop GIS application.
    2. Install and enable the 'Azure Maps Creator QGIS Plugin'.
    3. Go to 'Plugins' -> 'Azure Maps Creator Plugin' -> 'Azure Maps Creator Plugin' to open the plugin dialog.
    4. In the plugin dialog, locate the 'Logs Folder' section.
    5. Click on the 'Browse' button next to the 'Logs Folder' path.
    6. In the folder selection dialog, navigate to a writable directory outside of the QGIS plugin directory, for example, the user's 'Documents' directory or 'temp' directory. Select this directory and click 'Select Folder'.
    7. Click the 'Get Features' button in the plugin dialog to trigger a logging event. Ensure you have entered valid credentials to trigger plugin actions.
    8. Navigate to the directory you selected as the 'Logs Folder' in step 6 using your operating system's file explorer.
    9. Verify that a new log file (e.g., `AzureMaps_YYYYMMDD_HHMMSS.log`) has been created in the directory you specified.
    10. Open the log file and confirm it contains log entries from the plugin, proving that the plugin wrote a file to a user-defined location outside the intended plugin directory.