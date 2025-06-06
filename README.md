## Capstone 2 - Applying Machine Learning to enhance automated Incident Response

The entire source code runs on Python version 3.10.0.

### 1. Installing

The required library versions can be found in the requirements.txt file.

Run the following command in CMD to install the necessary libraries: `pip install -r requirements.txt`

### 2. Using

The Python scripts should be set up as follows:

#### 2.1. On Windows 10

Run the following command to compile the source code into an executable file: `pyinstaller -F /Extract_features_on_Windows10/delete-malware.py`

Then copy the generated file `/dist/delete-malware.exe` and paste it into the directory: `C:\Program Files (x86)\ossec-agent\active-response\bin\`

The script `/Extract_features_on_Windows10/PE_file_extract_features.py` can be executed by simply double-clicking it (or it can be compiled in the same way as the delete-malware script above).

#### 2.2. On Wazuh Server

When the web server is under attack, alert logs will appear on the Wazuh server. A script is required to monitor this alert log file and forward logs to the ML component via an API.

On the Wazuh server, execute the script `/Wazuh_Server_trigger_alert/trigger_alert_API.py` with the following steps:

- Grant execute permission: `chmod +x trigger_alert_API.py`

- Run the script: `./trigger_alert_API.py`

#### 2.3. On the Machine Learning system

Run the script `/Machine_Learning/app2.py` with the following command: `uvicorn app2:app --reload --host <ML_IP> --port 8000`, where *<ML_IP>* is the IP address of the ML server.

**Note: Make sure to update the IP addresses in the scripts to match your system configuration.**

