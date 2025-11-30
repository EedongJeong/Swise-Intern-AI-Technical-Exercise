import platform
import subprocess
import json
import getpass
import socket
from datetime import datetime, timezone

def get_current_timestamp():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

def get_installed_apps():
  #Retrieves a list of installed applications on Windows via PowerShell
    cmd = [
        "powershell", "-Command",
        "Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Select-Object DisplayName | ConvertTo-Json"
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        if not result.stdout.strip():
            return []
        data = json.loads(result.stdout)
        # Ensure we return a clean list of strings, filtering out empty names
        apps = [item["DisplayName"] for item in data if isinstance(item, dict) and item.get("DisplayName")]
        return apps
    except Exception as e:
        return [f"Error fetching apps: {str(e)}"]

def get_last_user():
#Retrieves the last logged-in user and timestamp
    return {
        "username": getpass.getuser(),
        "last_active": get_current_timestamp()
    }

def get_encryption():
    # Checks BitLocker status via PowerShell
    cmd = ["powershell", "-Command", "Get-BitLockerVolume | Select-Object -ExpandProperty ProtectionStatus"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True).stdout.strip()
        # "1" usually indicates On/Encrypted in PowerShell output for ProtectionStatus
        return "Yes" if "On" in result or "1" in result else "No"
    except:
        return "Unknown (Privileges required)"

def get_antivirus():
    # Checks Windows Defender status via PowerShell
    cmd = ["powershell", "-Command", "Get-MpComputerStatus | Select-Object -ExpandProperty AntivirusEnabled"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True).stdout.strip()
        return "Yes" if result == "True" else "No"
    except:
        return "Unknown"

def get_mdm():
    # Hardcoded for no (need to implement properly)
    return "No"

def get_system_update():
    # Checks for the last installed Windows Update via PowerShell
    cmd = [
        "powershell", "-Command",
        "Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1 -ExpandProperty InstalledOn"
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True).stdout.strip()
        if result:
            return f"Yes (Last hotfix: {result})"
        return "No"
    except:
        return "Unknown"

def get_device_health_status():
    # Check simple connectivity
    is_online = False
    try:
        # Pinging a DNS like 8.8.8.8 to check internet
        socket.create_connection(("8.8.8.8", 53), timeout=3)
        is_online = True
    except OSError:
        pass

    update_status = get_system_update()
    vulnerabilities = []
    
    if "No" in update_status or "Unknown" in update_status:
        vulnerabilities = ["CVE-2024-001: Old OS Kernel"]

    return {
        "status": "Online" if is_online else "Offline",
        "last_seen_online": get_current_timestamp(),
        "system_updated": update_status,
        "simulated_vulnerabilities": vulnerabilities
    }

def package_data():

    os_type = platform.system()
    
    # Verify we are on Windows before running Windows-specific commands
    if os_type != "Windows":
        return json.dumps({"error": "This agent is designed for Windows environments."})

    print(f"[*] Starting collection on {os_type}...")

    payload = {
        "device_id": socket.gethostname(),
        "collection_timestamp": get_current_timestamp(),
        "os_info": f"{os_type} {platform.release()}",
        "resource_collection": {
            "installed_applications": get_installed_apps(),
            "last_user_activity": get_last_user(),
            "system_configuration": {
                "encryption_enabled": get_encryption(),
                "antivirus_installed": get_antivirus(),
                "mdm_active": get_mdm()
            },
            "device_health": get_device_health_status()
        }
    }
    
    return json.dumps(payload, indent=4)

def receive_device_data(device_json_str):
    
    return json.loads(device_json_str)

def build_analysis_prompt(collected_data):

    prompt = (
        "You are a Cybersecurity Analyst.\n"
        "Analyse the provided device configuration JSON. Identify the most critical security finding and classify it.\n\n"
        "Device Data:\n"
        f"{json.dumps(collected_data, indent=4)}\n\n"
        "Return your answer as JSON with keys: insight, severity, finding_type."
    )
    return prompt

def simulate_ai_analysis(prompt):

    print("\n[Simulated AI Request]")
    print(prompt)

    simulated_response = {
        "insight": "Device encryption is disabled, making sensitive data vulnerable if the device is lost or stolen. This is a critical security policy"
        "violation",
        "severity": "Critical",
        "finding_type": "Misconfiguration"
    }

    print("\n[Simulated AI Response]")
    print(json.dumps(simulated_response, indent=4))

    return simulated_response

def display_security_insight(analysis_result):
    print("\n[Security Insight]")
    print(f"Insight: {analysis_result.get('insight')}")
    print(f"Severity: {analysis_result.get('severity')}")
    print(f"Finding Type: {analysis_result.get('finding_type')}")


if __name__ == "__main__":

    final_json = package_data()
    print(final_json)

    collected_data = receive_device_data(final_json)

    prompt = build_analysis_prompt(collected_data)

    analysis_output = simulate_ai_analysis(prompt)

    display_security_insight(analysis_output)

