# NinjaRMM API HIPAA Compliance Export
Author:  Al Robison

## Description
The HIPAA Compliance Exporter tool is a PowerShell script designed to facilitate the export of device information from the NinjaRMM platform for HIPAA compliance purposes. It retrieves device details via the NinjaRMM API, organizes the data, and exports it to a CSV file.

## Features
Creates a .csv file with the following information:
- Device name *(DeviceName)*
    - Exported from NinjaRMM
- Type *(DeviceType)*
    - Exported from NinjaRMM
- Activation status *(Activated)*
- Deactivation status *(Deactivated)*
- Asset tag *(AssetTag)*
- Make and model *(Model)*
    - Exported from NinjaRMM
- Serial number *(SerialNumber)*
    - Exported from NinjaRMM
- Location *(PhysicalLocation)*
    - Exported from NinjaRMM
- Last logged in user *(UserAssigned)*
    - Exported from NinjaRMM
- IP address *(LastIPAddress)*
    - Exported from NinjaRMM
- If device has access to Electronic Protected Health Information *(EPHI)*
- Antivirus status *(EndPointProtection)*
    - Exported from NinjaRMM
    - *Requires custom field: av_present*
- Encryption status *(Encryption)*
    - Exported from NinjaRMM
    - *Requires custom fields:*
        - *bitlocker*
        - *filevault*
- Risk rating *(RiskRating)*
- Custom notes *(Notes)*
Automated Data Comparison: Compare the latest device data with previous exports to identify any changes since the last export.
User-Friendly Interface: Utilizes a graphical user interface (GUI) to guide users through the export process, making it accessible to users with varying levels of technical expertise.

## Prerequisites
Before using this tool, ensure you have the following:
- NinjaRMM API Credentials: Obtain API credentials (client ID and client secret) with "monitoring" scope from your NinjaRMM account to authenticate API requests.
- NinjaRMM custom fields created: This script uses 3 custom fields to pull information...
    - av_present
        - Value should be "Yes" if your AV/EDR product is present on the device or "No" if it is not present.
    - bitlocker
        - Value should be "Yes" if the Windows device is encrypted with BitLocker or "No" if it is not present.
    - filevault
        - Value should be "Yes" if the MacOS device is encrypted with FileVault or "No" if it is not present.
    - It is recommended to use automated scripts to fill in this information. Unfortunately NinjaOne stopped the ability to pull BitLocker information via the API device details.
- PowerShell Environment: This script requires a PowerShell environment to execute. It has been tested on Windows PowerShell v5.1.

## Usage
1. **Before using this, make sure to read the "DISCLAIMER - SECURITY NOTICE" section fully**
2. Download the following files, keeping their folder structure intact:
    - HIPPA_Compliance_Exporter.ps1
    - settings.json
    - favicon.ico
    - Data\XYZ_DeviceExport_20240101-0123.csv  *(The actual file doesn't matter, but it shows what your output will look like)*
3. Create an accessible local or server folder where you can store previous data exports going forward.
    - Examples: "C:\LocalFiles" or "S:\HIPPA_EXPORT_DATA"
    - The exporter will look in this location for previously ran exports that have a matching name in order to compare changes.
    - It's not necessary to keep these exports longer than you need, but you will need to define a directory...
4. Edit settings.json and change the value for "server_drive" and "server_data_dir" to the directory you created in step 3.
    - Example 1:
        - `{
            "server_drive": "S:",
            "server_data_dir": "Device_Compliance_Data",
        }`
    - Example 2:
        - `{
            "server_drive": "C:",
            "server_data_dir": "LocalFiles",
        }`
5. Edit settings.json and add any organization names you need to export in your NinjaRMM instance:
    - Example:
        - `"orgs": [
            "Company A",
            "Company B",
            "Company C"
        ]`
6. Run 'HIPAA_Compliance_Exporter.ps1'
    - Using the Powershell console, navigate to the .ps1 file and run:
        - cd "C:\Path\To\HIPAA_Compliance_Exporter.ps1"
        - .\HIPAA_Compliance_Exporter.ps1
    - Using File Explorer, navigate to the .ps1 file, right-click and choose "Run with PowerShell".
    - If the directory you created in step 3 uses a shared/mapped drive, ensure the .ps1 file is ran as an instance with permissions to that drive. (i.e., If the drive was mapped to your account, do NOT run Powershell as admin because the admin instance may not have the same drive maps you have.)
7. Follow On-Screen Instructions: The script will guide you through the export process using the graphical user interface.

## DISCLAIMER - SECURITY NOTICE
- **The exporter performs no additional credential encryption.**
- API credentials are entered in plain text in the GUI and passed as part of the request body to the NinjaRMM API endpoint.
- Since the credentials are transmitted as plain text, they are potentially susceptible to interception if transmitted over an unsecured connection or stored insecurely.
- The API request is sent using 'Invoke-RestMethod' to NinjaRMM's HTTPS endpoints. It is your responsibility to ensure a secure connection.
- This script is provided as is without warranty. The user assumes all risks associated with its use.
- **USE AT YOUR OWN RISK!!!**

## License
This project is licensed under the GNU General Public License v3.0 - see the LICENSE file for details.

## Acknowledgements
This script utilizes the NinjaRMM API to retrieve device information. Special thanks to NinjaRMM for providing access to their platform via API.