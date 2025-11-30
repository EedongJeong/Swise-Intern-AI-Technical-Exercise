import platform
import subprocess
import json
import getpass
import socket
from datetime import datetime, timezone
from openai import OpenAI
import os

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

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

def analyze_with_openai(prompt):
    print("\n[*] Sending data to OpenAI API...")
    
    if not client.api_key:
        return {"error": "OpenAI API Key not found. Set OPENAI_API_KEY env variable."}

    try:
        response = client.chat.completions.create(
            model="gpt-4o",  
            messages=[
                {"role": "system", "content": "You are a helpful security assistant. You must output JSON."},
                {"role": "user", "content": prompt}
            ],
            response_format={"type": "json_object"}, # Critical for ensuring JSON output
            temperature=0.2, 
        )
        
        content = response.choices[0].message.content
        return json.loads(content)
        
    except Exception as e:
        print(f"Error calling OpenAI: {e}")
        return {
            "insight": "API Call Failed",
            "severity": "Unknown",
            "finding_type": "Error"
        }

def display_security_insight(analysis_result):
    print(" \n  CYBER SECURITY ANALYST REPORT")
    print(f"INSIGHT:      {analysis_result.get('insight', 'N/A')}")
    print(f"SEVERITY:     {analysis_result.get('severity', 'N/A')}")
    print(f"FINDING TYPE: {analysis_result.get('finding_type', 'N/A')}")

if __name__ == "__main__":

    final_json = package_data()
    print(final_json)

    collected_data = receive_device_data(final_json)

    prompt = build_analysis_prompt(collected_data)

    analysis_output = analyze_with_openai(prompt)

    display_security_insight(analysis_output)

