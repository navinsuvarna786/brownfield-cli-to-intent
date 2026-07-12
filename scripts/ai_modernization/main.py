import argparse
import sys
import os

# Fix for potential Torch/Triton conflict: import torch early
try:
    import torch  # type: ignore
except ImportError:
    pass

import pandas as pd
import json
import yaml
import getpass
from typing import List, Dict, Optional

# Ensure local imports work
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from models import AgentState
from agents import app
from connector import fetch_config_from_device

# Vendor/device type choices for the multi-agent system
VENDOR_DEVICE_CHOICES = [
    {"vendor": "cisco", "device": "Cisco Catalyst 3850 Series Switches (Legacy)", "label": "Cisco, 3850"},
    {"vendor": "arista", "device": "Arista CCS-720XP-24ZY4", "label": "Arista, CCS-720XP-24ZY4"},
    {"vendor": "juniper", "device": "Juniper Networks Switch", "label": "Juniper"},
    {"vendor": "unknown", "device": "Unknown Device", "label": "Unknown (LLM fallback)"},
]


def get_vendor_and_device_type(default_type: Optional[str] = None):
    """Ask the user to select vendor and device type.
    
    Returns:
        tuple: (vendor, device_type) e.g. ("cisco", "Cisco Catalyst 3850 ...")
    """
    if default_type:
        # Try to match default_type to a known choice
        for choice in VENDOR_DEVICE_CHOICES:
            if default_type.lower() in choice["device"].lower() or default_type.lower() in choice["label"].lower():
                return choice["vendor"], choice["device"]
        # If no match, assume cisco by default
        return "cisco", default_type

    print("\nSelect Source Vendor and Device Type:")
    for idx, choice in enumerate(VENDOR_DEVICE_CHOICES):
        print(f"  {idx + 1}. {choice['label']}")

    selection = input("\nEnter number (or press Enter for default 'Cisco, 3850'): ").strip()

    if not selection:
        chosen = VENDOR_DEVICE_CHOICES[0]
        return chosen["vendor"], chosen["device"]

    try:
        idx = int(selection) - 1
        if 0 <= idx < len(VENDOR_DEVICE_CHOICES):
            chosen = VENDOR_DEVICE_CHOICES[idx]
            return chosen["vendor"], chosen["device"]
    except ValueError:
        pass

    print("Invalid selection, defaulting to Cisco, 3850.")
    chosen = VENDOR_DEVICE_CHOICES[0]
    return chosen["vendor"], chosen["device"]


TARGET_PLATFORM_CHOICES = [
    "Cisco Catalyst 9300 Series Switches",
    "Cisco Catalyst 9400 Series Switches",
    "Cisco Catalyst 9500 Series Switches",
    "Cisco Catalyst 9600 Series Switches",
    "Cisco Catalyst 3850 Series Switches (Legacy)",
    "Other (Type manually)",
]


def get_target_platform(default_target: Optional[str] = None):
    """Ask the user to select the target platform for migration.
    
    Returns:
        str: Target platform name e.g. "Cisco Catalyst 9300 Series Switches"
    """
    if default_target:
        return default_target

    print("\nSelect Target Platform (migration destination):")
    for idx, opt in enumerate(TARGET_PLATFORM_CHOICES):
        print(f"  {idx + 1}. {opt}")

    selection = input("\nEnter number (or press Enter for default 'Cisco Catalyst 9300'): ").strip()

    if not selection:
        return "Cisco Catalyst 9300 Series Switches"

    try:
        idx = int(selection) - 1
        if 0 <= idx < len(TARGET_PLATFORM_CHOICES) - 1:
            return TARGET_PLATFORM_CHOICES[idx]
        elif idx == len(TARGET_PLATFORM_CHOICES) - 1:
            return input("Enter custom target platform: ").strip()
    except ValueError:
        pass

    print("Invalid selection, defaulting to Cisco Catalyst 9300.")
    return "Cisco Catalyst 9300 Series Switches"

def process_config_content(raw_config: str, source_name: str, device_type: str, output_dir: str, vendor: str = "cisco", target_platform: str = "Cisco Catalyst 9300 Series Switches"):
    """Core function to run the AI agent on a config string."""
    print(f"\nProcessing: {source_name} -> Vendor: {vendor} -> Source: {device_type} -> Target: {target_platform}")
    
    # Initialize full state
    initial_state = AgentState(
        raw_config=raw_config,
        source_filename=source_name,
        target_device_type=target_platform,
        source_vendor=vendor,
        trace_log=[],
        legacy_parsed_data={},
        extracted_intent={},
        decision_metadata=[],
        normalized_intent={},
        validation_result=None,
        iteration_count=0,
        rag_context="",
        final_yaml_output="",
        final_output_path="",
        report_path=""
    )
    
    try:
        # Run the graph
        final_state = app.invoke(initial_state)
        
        # Extract results
        val = final_state.get("validation_result", {})
        score = val.get("score", 0.0) if val else 0.0
        
        print(f"  -> Process Complete. Confidence Score: {score:.2f}")
        
        if val and not val.get("valid", False):
            print("  -> Warning: Validation had issues.")
            for issue in val.get("issues", []):
                print(f"     - [{issue.get('severity')}] {issue['message']}")
        
        final_path = final_state.get("final_output_path")
        if final_path:
            print(f"  -> Generated YAML: {final_path}")
        else:
            print("  -> No final YAML generated (likely due to validation failure).")
            
        report_path = final_state.get("report_path")
        if report_path:
            print(f"  -> Report: {report_path}")

        return final_path
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        print(f"  -> Error processing {source_name}: {e}")
        return None

def process_file(file_path: str, device_type: str, output_dir: str, vendor: str = "cisco", target_platform: str = "Cisco Catalyst 9300 Series Switches"):
    if not os.path.exists(file_path):
        print(f"Error: File {file_path} not found.")
        return

    with open(file_path, 'r') as f:
        raw_config = f.read()

    process_config_content(raw_config, os.path.basename(file_path), device_type, output_dir, vendor=vendor, target_platform=target_platform)

def process_folder(folder_path: str, device_type: str, output_dir: str, vendor: str = "cisco", target_platform: str = "Cisco Catalyst 9300 Series Switches"):
    print(f"\nScanning folder: {folder_path}")
    if not os.path.exists(folder_path):
        print(f"Error: Folder {folder_path} not found.")
        return
        
    # Walk through directory recursively or just list files? Prompt implied multiple files in folder.
    # Simple listdir for now to handle flat structure, or os.walk if deeper.
    config_extensions = ('.txt', '.cfg', '.conf', '.ios', '.log')
    files_processed = 0
    
    for root, dirs, files in os.walk(folder_path):
        for file in files:
            if file.endswith(config_extensions):
                full_path = os.path.join(root, file)
                process_file(full_path, device_type, output_dir, vendor=vendor, target_platform=target_platform)
                files_processed += 1
                
    if files_processed == 0:
        print("No config files found in folder.")

def process_ssh_single(ip, user, password, secret, netmiko_type, intent_device_type, output_dir, vendor: str = "cisco", target_platform: str = "Cisco Catalyst 9300 Series Switches"):
    try:
        config = fetch_config_from_device(ip, user, password, secret, device_type=netmiko_type)
        if config:
            process_config_content(config, f"{ip}_ssh_config", intent_device_type, output_dir, vendor=vendor, target_platform=target_platform)
        else:
            print(f"Failed to retrieve config from {ip}")
    except Exception as e:
        print(f"Failed to process SSH device {ip}: {e}")

def process_csv(csv_path: str, default_intent_type: str, output_dir: str, vendor: str = "cisco", target_platform: str = "Cisco Catalyst 9300 Series Switches"):
    print(f"\nProcessing Batch from CSV: {csv_path}")
    if not os.path.exists(csv_path):
        print(f"Error: CSV file {csv_path} not found.")
        return

    try:
        df = pd.read_csv(csv_path)
        # Normalize column names to lowercase for easier matching
        df.columns = [c.lower().strip() for c in df.columns]
        cols = df.columns
        
        # Mode 2: SSH Batch (Priority if IP present)
        if 'ip' in cols or 'mgmt_ip' in cols:
            print("  -> Detected SSH Batch Columns")
            ip_col = 'ip' if 'ip' in cols else 'mgmt_ip'
            
            for i, (_, row) in enumerate(df.iterrows()):
                ip = str(row[ip_col]).strip()
                if not ip or ip.lower() == 'nan': continue
                
                user = str(row.get('username', '')).strip()
                pwd = str(row.get('password', '')).strip()
                secret = str(row.get('secret', '')).strip()
                
                # Device type for Netmiko (driver)
                netmiko_type = str(row.get('netmiko_platform', 'cisco_ios')).strip()
                
                # Device type for Intent Generation (LLM Context)
                intent_type = str(row.get('target_device_type', default_intent_type)).strip()
                if intent_type.lower() == 'nan': intent_type = default_intent_type
                
                if not user or not pwd:
                    print(f"Skipping {ip}: Missing username or password in CSV.")
                    continue
                    
                print(f"\n--- Batch Item {i+1}: {ip} ---")
                process_ssh_single(ip, user, pwd, secret, netmiko_type, intent_type, output_dir, vendor=vendor, target_platform=target_platform)

        # Mode 1: File Batch
        elif 'file_path' in cols or 'filename' in cols:
            print("  -> Detected File Batch Columns")
            path_col = 'file_path' if 'file_path' in cols else 'filename'
            for i, (_, row) in enumerate(df.iterrows()):
                path = str(row[path_col]).strip()
                if not path or path.lower() == 'nan': continue
                
                intent_type = str(row.get('target_device_type', default_intent_type)).strip()
                if intent_type.lower() == 'nan': intent_type = default_intent_type
                
                print(f"\n--- Batch Item {i+1}: {path} ---")
                process_file(path, intent_type, output_dir, vendor=vendor, target_platform=target_platform)
        else:
            print("Error: CSV format not recognized.")
            print("Required columns for SSH: 'ip' (or 'mgmt_ip'), 'username', 'password'")
            print("Required columns for Files: 'file_path' (or 'filename')")
            
    except Exception as e:
        print(f"Error reading/processing CSV: {e}")

def main():
    parser = argparse.ArgumentParser(description="AI-Driven Legacy Config Migration Tool")
    
    # Input arguments
    parser.add_argument("--input", help="Path to a single config file, folder, or CSV file.")
    
    # Single SSH arguments
    parser.add_argument("--ssh-ip", help="IP address for single device SSH connection.")
    parser.add_argument("--ssh-user", help="SSH Username")
    parser.add_argument("--ssh-pass", help="SSH Password (will prompt if missing)")
    parser.add_argument("--ssh-secret", help="SSH Enable Secret")
    parser.add_argument("--netmiko-type", default="cisco_ios", help="Netmiko driver type (default: cisco_ios)")

    # General arguments
    parser.add_argument("--output-dir", default="./output", help="Directory to save YAML intent files")
    parser.add_argument("--device-type", dest="device_type", help="Source device type (e.g. 'Arista CCS-720XP-24ZY4')")
    parser.add_argument("--target-platform", dest="target_platform", help="Target platform for migration (e.g. 'Cisco Catalyst 9300')")
    
    args = parser.parse_args()
    print(f"DEBUG: Parsed args: {args}")
    
    # Ensure output directory exists
    os.makedirs(args.output_dir, exist_ok=True)
    
    # Determine source vendor and device type
    vendor, intent_device_type = get_vendor_and_device_type(args.device_type)
    
    # Determine target platform
    target_platform = get_target_platform(args.target_platform)
    
    print(f"Using Source Vendor: {vendor}")
    print(f"Using Source Device: {intent_device_type}")
    print(f"Using Target Platform: {target_platform}")
    if vendor == "arista":
        print("  -> Arista detected: will skip Legacy Parser (Agent 1) and start at Intent Mapper (Agent 2).")
    
    # Priority 1: SSH Single via Args
    if args.ssh_ip:
        username = args.ssh_user
        password = args.ssh_pass
        
        if not username:
            username = input("Enter SSH Username: ").strip()
        if not password:
            password = getpass.getpass("Enter SSH Password: ").strip()
            
        process_ssh_single(
            args.ssh_ip, 
            username, 
            password, 
            args.ssh_secret, 
            args.netmiko_type, 
            intent_device_type, 
            args.output_dir,
            vendor=vendor,
            target_platform=target_platform
        )
        return

    # Priority 2: Input Path (File, Folder, CSV)
    input_path = args.input
    if not input_path:
        # Interactive Helper
        print("\nNo input argument provided.")
        print("Supported modes:")
        print(" 1. Single File (enter path)")
        print(" 2. Folder of Configs (enter path)")
        print(" 3. CSV Batch File (enter path)")
        print(" 4. Manual SSH (type 'ssh')")
        
        user_input = input("\nEnter path or command: ").strip()
        
        if user_input.lower() == 'ssh':
            # Interactive manual SSH
            ip = input("Enter Device IP: ").strip()
            user = input("Enter SSH Username: ").strip()
            pwd = getpass.getpass("Enter SSH Password: ").strip()
            secret = getpass.getpass("Enter Enable Secret (optional): ").strip()
            process_ssh_single(ip, user, pwd, secret, "cisco_ios", intent_device_type, args.output_dir, vendor=vendor, target_platform=target_platform)
            return
        else:
            input_path = user_input

    if input_path.endswith('.csv'):
        # Mode 3 & 4 (CSV File/SSH)
        process_csv(input_path, intent_device_type, args.output_dir, vendor=vendor, target_platform=target_platform)
        
    elif os.path.isdir(input_path):
        # Mode 2: Folder Batch
        process_folder(input_path, intent_device_type, args.output_dir, vendor=vendor, target_platform=target_platform)
        
    elif os.path.isfile(input_path):
        # Mode 1: Single File
        process_file(input_path, intent_device_type, args.output_dir, vendor=vendor, target_platform=target_platform)
    else:
        print(f"Error: Path '{input_path}' does not exist or is invalid.")

if __name__ == "__main__":
    main()
