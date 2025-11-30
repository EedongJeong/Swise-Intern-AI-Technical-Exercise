import platform
import subprocess
import json
import getpass
import socket
from datetime import datetime, timezone

def get_current_timestamp():
    """Helper for UTC timestamp."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

def get_installed_apps_windows():
    """
    Fetches installed applications via PowerShell registry lookup.
    """
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
    """
    Returns current user and timestamp.
    """
    return {
        "username": getpass.getuser(),
        "last_active": get_current_timestamp()
    }

def get_encryption_status_windows():
    """
    Checks BitLocker status via PowerShell.
    """
    cmd = ["powershell", "-Command", "Get-BitLockerVolume | Select-Object -ExpandProperty ProtectionStatus"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True).stdout.strip()
        # "1" usually indicates On/Encrypted in PowerShell output for ProtectionStatus
        return "Yes" if "On" in result or "1" in result else "No"
    except:
        return "Unknown (Privileges required)"

def get_antivirus_windows():
    """
    Checks MpComputerStatus for Windows Defender/AV status.
    """
    cmd = ["powershell", "-Command", "Get-MpComputerStatus | Select-Object -ExpandProperty AntivirusEnabled"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True).stdout.strip()
        return "Yes" if result == "True" else "No"
    except:
        return "Unknown"

def get_mdm_status_windows():
    """
    Checks for Work/School account connection (Azure AD/Intune) using dsregcmd.
    """
    try:
        # dsregcmd /status output contains "AzureAdJoined : YES" or "EnterpriseJoined : YES"
        result = subprocess.run(["dsregcmd", "/status"], capture_output=True, text=True).stdout
        if "AzureAdJoined : YES" in result or "EnterpriseJoined : YES" in result:
            return "Yes (AzureAD/Intune)"
        return "No"
    except FileNotFoundError:
        return "No (Command not found)"

def get_system_update_status_windows():
    """
    Checks the installation date of the last HotFix.
    """
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
    """
    Aggregates online status and simulated vulnerabilities (as per prompt requirements).
    """
    # Check simple connectivity
    is_online = False
    try:
        # Pinging a reliable DNS like 8.8.8.8 to check internet
        socket.create_connection(("8.8.8.8", 53), timeout=3)
        is_online = True
    except OSError:
        pass

    # Note: Real vulnerability scanning requires a CVE database. 
    # Per instructions, we simulate this list based on system update status.
    update_status = get_system_update_status_windows()
    vulnerabilities = []
    
    if "No" in update_status or "Unknown" in update_status:
        vulnerabilities = ["CVE-2024-001: Potential Outdated OS Kernel"]

    return {
        "status": "Online" if is_online else "Offline",
        "last_seen_online": get_current_timestamp(),
        "system_updated": update_status,
        "simulated_vulnerabilities": vulnerabilities
    }

def package_data():
    """
    Aggregates all data into the final JSON structure for the API.
    """
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
            "installed_applications": get_installed_apps_windows(),
            "last_user_activity": get_last_user(),
            "system_configuration": {
                "encryption_enabled": get_encryption_status_windows(),
                "antivirus_installed": get_antivirus_windows(),
                "mdm_active": get_mdm_status_windows()
            },
            "device_health": get_device_health_status()
        }
    }
    
    return json.dumps(payload, indent=4)

def receive_device_data(device_json_str):
    """
    Accepts packaged JSON string from the Local Agent
    and parses it into a Python dictionary.
    """
    try:
        return json.loads(device_json_str)
    except json.JSONDecodeError:
        return {"error": "Invalid JSON received by analysis module."}


def build_analysis_prompt(collected_data):
    """
    Builds a single structured prompt instructing the LLM
    to act as a cybersecurity analyst.
    """
    prompt = (
        "You are a Cybersecurity Analyst.\n"
        "Analyse the provided device configuration JSON. Identify the most critical "
        "security finding and classify it.\n\n"
        "Device Data:\n"
        f"{json.dumps(collected_data, indent=4)}\n\n"
        "Return your answer as JSON with keys: insight, severity, finding_type."
    )
    return prompt

def simulate_openai_analysis(prompt):
    """
    This function **simulates** what an OpenAI API call would return.
    In the real implementation, this is where we would call the OpenAI API.

    For assignment purposes, we return a static expected response based
    on likely vulnerabilities from the Local Agent data.
    """

    print("\n[Simulated OpenAI Request]")
    print("Prompt sent to LLM:")
    print(prompt)

    # Simulated static LLM output
    simulated_response = {
        "insight": "Device encryption is disabled, making sensitive data vulnerable if the device is lost or stolen.",
        "severity": "Critical",
        "finding_type": "Misconfiguration"
    }

    print("\n[Simulated OpenAI Response]")
    print(json.dumps(simulated_response, indent=4))

    return simulated_response

def display_security_insight(analysis_result):
    """
    Prints summary of the simulated LLM analysis.
    """
    print("\n=== Security Analysis Result ===")
    print(f"Insight: {analysis_result.get('insight')}")
    print(f"Severity: {analysis_result.get('severity')}")
    print(f"Finding Type: {analysis_result.get('finding_type')}")


if __name__ == "__main__":
    # Execute the collection and print the result (Part 1)
    final_json = package_data()
    print(final_json)

    # === PART 2: Analysis Module ===

    # 1. Receive and parse agent data
    collected_data = receive_device_data(final_json)

    # 2. Build structured analyst prompt
    prompt = build_analysis_prompt(collected_data)

    # 3. Simulated OpenAI LLM Analysis
    analysis_output = simulate_openai_analysis(prompt)

    # 4. Display the simulated insight
    display_security_insight(analysis_output)

