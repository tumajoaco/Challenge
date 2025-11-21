#####README FILE##########################

Author: JT
CreatedDate: 21/11/2025
LastUpdatedDate: 21/11/2025

############################################
MODULES:

Required libraries:
    - sys
    - json
    - yaml
    - os
    - jinja2
    - datetime

Installation command -> pip install PyYAML Jinja2

#############
CONFIGURATION:

1. Open MainConfig.yaml and update variables if it is needed:
    - FoldersPath:
       - CONFIG_FOLDER="./Config"                                    -> This folder is used to store config files: allowlist.yml, connectors.yml, mitre_map.yaml.
       - ALERT_FOLDER="./Alerts"                                     -> This folder is used to store alerts that will be processed.
       - INCIDENT_FOLDER="./out/incidents"                           -> This folder is used to store generated incidents in json format.
       - SUMMARY_FOLDER="./out/summaries"                            -> This folder is used to store generated incidents in md format.
       - LOG_FOLDER="./out"                                          -> This folder is used to store logs files and out folder.
    - FilesNames:
       - CONNECTORS_FILENAME="connectors.yml"                        -> File name that will be used to configure Threat Intelligence connectors.
       - ALLOWLIST_FILENAME="allowlists.yml"                         -> File name that will be used to configure allowlisted IOC and assets.
       - MITRE_FILENAME="mitre_map.yml"                              -> File name that will be used to link alert types with mitre framework techniques.
       - MARKDOWN_TEMPLATE_FILENAME="summary_template.md"            -> File name that will be used to define markdown template.

3. Update Connectors file with your TI providers respecting the following format:
    providers:
      WriteYourProviderName:
        base_url: "file://mocks/ti"

4. Create or update mock it files in /mocks/ti path. File names should have the following format: #TI-PROVIDER#_#IOC-TYPE#_#IOC-VALUE#
    - TI-PROVIDER: must exist in Connectors file name
    - IOC-TYPE: ip|url|domain|sha256 
    - IOC-VALUE: IOC value, i.e.: 1.1.1.1

    - Example:
        - FileName: anomali_ip_1.2.3.4.json
        - Content: { "ip": "1.2.3.4", "confidence": 80, "risk": "suspicious", "sightings": 12 }

NOTE: Respect the format of each file.

4. Update allow list file using the existence format.

5. Update markdown template based on your requirements.
#############
FOLDER STRUCTURE:

    /Project Root Folder
    |
    |_/Alerts
    |        |_/AlertFile.json
    |
    |_/Config
    |        |_/allowlist.yml
    |        |_/connectors.yml
    |        |_/mitre_map.yml
    |
    |_/mocks
    |        |_/ti
    |             |_/TI-ProviderName1_IocType1_IocValue1.json
    |             |_/TI-ProviderName2_IocType2_IocValue2.json
    |_/out
    |     |_/incidents
    |                 |_/inc-001.json
    |                 |_/inc-002.json
    |     |_/summaries
    |                 |_/inc-001.md
    |                 |_/inc-002.md
    |     |_/logs.txt
    |     |_/isolation.txt
    |_/MainConfig.yaml
    |_/Main.py
    |_/ReadMe.txt

#############

EXECUTION COMMAND:
    - python.exe .\Main.py alerts/sentinel.json
